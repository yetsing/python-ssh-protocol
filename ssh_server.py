"""
实现一个 ssh server

ssh 涉及的 rfc 列表: https://www.omnisecu.com/tcpip/important-rfc-related-with-ssh.php
The Secure Shell (SSH) Protocol Assigned Numbers: https://datatracker.ietf.org/doc/html/rfc4250
The Secure Shell (SSH) Protocol Architecture: https://datatracker.ietf.org/doc/html/rfc4251
The Secure Shell (SSH) Authentication Protocol: https://datatracker.ietf.org/doc/html/rfc4252
The Secure Shell (SSH) Transport Layer Protocol: https://datatracker.ietf.org/doc/html/rfc4253
The Secure Shell (SSH) Connection Protocol: https://datatracker.ietf.org/doc/html/rfc4254

"""
import abc
import base64
import dataclasses
import enum
import hashlib
import hmac
import os
import pathlib
import secrets
import shlex
import socket
import socketserver
import struct
import subprocess
import tempfile
import typing as t

import cryptography.exceptions
from cryptography.hazmat.primitives import hashes, poly1305, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import logutil
from error import (
    BadRequestError,
    DisconnectError,
    PacketTooLargeError,
    UnexpectedError,
    UnsupportedError,
)
from message import Message, SSHDisconnectReasonID, SSHMessageID

logger = logutil.get_logger(__name__)

# 当前文件所在文件夹
FILE_DIR = pathlib.Path(__file__).resolve().parent
SSH_DIR = FILE_DIR / "etc/ssh/"


def _expect(cond: bool, msg: str):
    if not cond:
        raise UnexpectedError(msg)


def _expect_eq(got, expected):
    cond = got == expected
    msg = f"expected <{expected}>, but got <{got}>"
    _expect(cond, msg)


@dataclasses.dataclass
class AdoptedAlgorithm:
    kex: str = ""
    server_host_key: str = ""
    # cs: client_to_server
    # sc: server_to_client
    encryption_cs: str = ""
    encryption_sc: str = ""
    mac_cs: str = ""
    mac_sc: str = ""
    compression_cs: str = ""
    compression_sc: str = ""
    language_cs: str = ""
    language_sc: str = ""


class SSHSide(enum.Enum):
    server = enum.auto()
    client = enum.auto()


@dataclasses.dataclass
class KexResult:
    side: SSHSide
    # 密钥交换对象
    kex: t.Optional["KeyExchangeInterface"]
    # shared secret, mpint 格式
    K: bytes
    H: bytes
    session_id: bytes

    def compute_key(self, key_size: int, tag: bytes) -> bytes:
        """计算密钥。计算方法如下

        o  Initial IV client to server: HASH(K || H || "A" || session_id)
        (Here K is encoded as mpint and "A" as byte and session_id as raw
        data.  "A" means the single character A, ASCII 65).

        o  Initial IV server to client: HASH(K || H || "B" || session_id)

        o  Encryption key client to server: HASH(K || H || "C" || session_id)

        o  Encryption key server to client: HASH(K || H || "D" || session_id)

        o  Integrity key client to server: HASH(K || H || "E" || session_id)

        o  Integrity key server to client: HASH(K || H || "F" || session_id)

        如果长度不够，可以按下面的算法计算

        K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
        K2 = HASH(K || H || K1)
        K3 = HASH(K || H || K1 || K2)
        ...
        key = K1 || K2 || K3 || ...

        ref: https://datatracker.ietf.org/doc/html/rfc4253#section-7.2

        Args:
            key_size: 生成的 key 大小，-1 表示使用默认大小
            tag: 标记符，就是上面提到的 "A" "B" "C" "D" 等等。

        Returns: 密钥
        """
        hash_func = self.kex.do_hash
        key = hash_func(self.K + self.H + tag + self.session_id)
        kx = key
        while len(key) < key_size:
            hk = hash_func(self.K + self.H + kx)
            kx += hk
            key += hk
        return key[:key_size]


class KeyExchangeInterface(abc.ABC):
    """密钥交换接口"""

    @abc.abstractmethod
    def __init__(self, transport: "SSHServerTransport", session_id: t.Optional[bytes]):
        raise NotImplementedError("__init__")

    @abc.abstractmethod
    def do_server_exchange(self) -> "KexResult":
        raise NotImplementedError("start_server")

    @abc.abstractmethod
    def do_client_exchange(self) -> "KexResult":
        raise NotImplementedError("start_client")

    @abc.abstractmethod
    def do_hash(self, b: bytes) -> bytes:
        raise NotImplementedError("do_hash")


class Curve25519Sha256Kex(KeyExchangeInterface):
    """curve25519-sha256 密钥交换算法

    curve25519 密钥交换的一些不同的地方
    https://datatracker.ietf.org/doc/html/rfc8731#section-3
    """

    def __init__(self, transport: "SSHServerTransport", session_id: t.Optional[bytes]):
        self.transport = transport
        self.kex_result = KexResult(
            transport.side,
            self,
            b"",
            b"",
            b"",
        )
        if session_id:
            self.kex_result.session_id = session_id
        self.kex_result.kex = self

        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self._q_c = b""
        self._k_s = b""
        self._q_s = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._h = b""

        self.host_key = self.transport.get_server_host_key()

    def do_server_exchange(self) -> "KexResult":
        # client send SSH_MSG_KEX_ECDH_INIT
        #   byte     SSH_MSG_KEX_ECDH_INIT
        #   string   Q_C, client's ephemeral public key octet string
        init_message = self.transport.read_message(
            SSHMessageID.KEX_ECDH_INIT,
        )
        self._q_c = init_message.get_string()
        # server reply SSH_MSG_KEX_ECDH_REPLY
        #   byte     SSH_MSG_KEX_ECDH_REPLY
        #   string   K_S, server's public host key
        #   string   Q_S, server's ephemeral public key octet string .
        #   string   the signature on the exchange hash
        self._k_s = self.host_key.get_k_s()
        reply_message = Message()
        reply_message.add_message_id(SSHMessageID.KEX_ECDH_REPLY)
        reply_message.add_string(self._k_s)
        reply_message.add_string(self._q_s)
        reply_message.add_string(self._get_signature_on_exchange_hash())
        self.transport.write_message(reply_message)
        return self.kex_result

    def do_client_exchange(self) -> "KexResult":
        pass

    def _get_signature_on_exchange_hash(self):
        """the signature on the exchange hash

        The exchange hash H is computed as the hash of the concatenation of
        the following.

          string   V_C, client's identification string (CR and LF excluded)
          string   V_S, server's identification string (CR and LF excluded)
          string   I_C, payload of the client's SSH_MSG_KEXINIT
          string   I_S, payload of the server's SSH_MSG_KEXINIT
          string   K_S, server's public host key
          string   Q_C, client's ephemeral public key octet string.
          string   Q_S, server's ephemeral public key octet string
          mpint    K,   shared secret
        """
        # 计算共享密钥
        client_key = X25519PublicKey.from_public_bytes(self._q_c)
        k = self.private_key.exchange(client_key)
        k = Message.bytes_to_mpint(k)
        self.kex_result.K = k

        # exchange hash
        m = Message()
        m.add_string(self.transport.client_version_data)
        m.add_string(self.transport.server_version_data)
        m.add_string(self.transport.client_algorithms_message.as_bytes())
        m.add_string(self.transport.server_algorithms_message.as_bytes())
        m.add_string(self._k_s)
        m.add_string(self._q_c)
        m.add_string(self._q_s)
        m.add_raw_bytes(k)

        # 如果这是第一次密钥交换，那么这个 exchange_hash 也是 session_id(rfc 文档里面提到的 session_identifier)
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(m.as_bytes())
        # print('m', m)
        exchange_hash = hasher.finalize()
        self.kex_result.H = exchange_hash
        if not self.kex_result.session_id:
            self.kex_result.session_id = exchange_hash

        sig = self.host_key.get_sign(exchange_hash)
        return sig

    def do_hash(self, b: bytes) -> bytes:
        return hashlib.sha256(b).digest()


class EcdhSha2Nistp256Kex(KeyExchangeInterface):
    """
    椭圆曲线的不同类别名字的对应 https://datatracker.ietf.org/doc/html/rfc4492#appendix-A

    不同类别椭圆曲线使用的 hash 算法
    https://www.rfc-editor.org/rfc/inline-errata/rfc5656.html
    6.2.1.  Elliptic Curve Digital Signature Algorithm
    +----------------+----------------+
    |   Curve Size   | Hash Algorithm |
    +----------------+----------------+
    |    b <= 256    |     SHA-256    |
    |                |                |
    | 256 < b <= 384 |     SHA-384    |
    |                |                |
    |     384 < b    |     SHA-512    |
    +----------------+----------------+
    """

    hash_call = hashlib.sha256
    curve_cls = ec.SECP256R1

    def __init__(self, transport: "SSHServerTransport", session_id: t.Optional[bytes]):
        self.transport = transport
        self.kex_result = KexResult(
            transport.side,
            self,
            b"",
            b"",
            b"",
        )
        if session_id:
            self.kex_result.session_id = session_id
        self.kex_result.kex = self

        self.private_key = ec.generate_private_key(
            self.curve_cls(),
        )
        self.public_key = self.private_key.public_key()

        self._q_c = b""
        self._k_s = b""
        self._q_s = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        self._h = b""

        self.host_key = None
        if transport.side == SSHSide.server:
            self.host_key = self.transport.get_server_host_key()

    def do_server_exchange(self) -> "KexResult":
        # client send SSH_MSG_KEX_ECDH_INIT
        #   byte     SSH_MSG_KEX_ECDH_INIT
        #   string   Q_C, client's ephemeral public key octet string
        init_message = self.transport.read_message(
            SSHMessageID.KEX_ECDH_INIT,
        )
        self._q_c = init_message.get_string()
        # server reply SSH_MSG_KEX_ECDH_REPLY
        #   byte     SSH_MSG_KEX_ECDH_REPLY
        #   string   K_S, server's public host key
        #   string   Q_S, server's ephemeral public key octet string .
        #   string   the signature on the exchange hash
        self._k_s = self.host_key.get_k_s()
        reply_message = Message()
        reply_message.add_message_id(SSHMessageID.KEX_ECDH_REPLY)
        reply_message.add_string(self._k_s)
        reply_message.add_string(self._q_s)
        reply_message.add_string(self._get_signature_on_exchange_hash())
        self.transport.write_message(reply_message)
        return self.kex_result

    def do_client_exchange(self) -> "KexResult":
        pass

    def _get_shared_secret(self):
        client_key = ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve_cls(), self._q_c
        )
        k = self.private_key.exchange(ec.ECDH(), client_key)
        return k

    def _get_signature_on_exchange_hash(self):
        """the signature on the exchange hash

        The exchange hash H is computed as the hash of the concatenation of
        the following.

          string   V_C, client's identification string (CR and LF excluded)
          string   V_S, server's identification string (CR and LF excluded)
          string   I_C, payload of the client's SSH_MSG_KEXINIT
          string   I_S, payload of the server's SSH_MSG_KEXINIT
          string   K_S, server's public host key
          string   Q_C, client's ephemeral public key octet string.
          string   Q_S, server's ephemeral public key octet string
          mpint    K,   shared secret
        """
        # print("\n\n_get_signature_on_exchange_hash")
        # 计算共享密钥
        k = self._get_shared_secret()
        # print("shared_secret", k)
        k = Message.bytes_to_mpint(k)
        self.kex_result.K = k

        # exchange hash
        m = Message()
        m.add_string(self.transport.client_version_data)
        # print("V_C", self.transport.client_version_data)
        m.add_string(self.transport.server_version_data)
        # print("V_S", self.transport.server_version_data)
        m.add_string(self.transport.client_algorithms_message.as_bytes())
        # print("I_C", self.transport.client_algorithms_message.as_bytes())
        m.add_string(self.transport.server_algorithms_message.as_bytes())
        # print("I_S", self.transport.server_algorithms_message.as_bytes())
        m.add_string(self._k_s)
        # print("K_S", self._k_s)
        m.add_string(self._q_c)
        # print("Q_C", self._q_c)
        m.add_string(self._q_s)
        # print("Q_S", self._q_s)
        m.add_raw_bytes(k)
        # print("K", k)
        # print("message", m.as_bytes())

        # 如果这是第一次密钥交换，那么这个 exchange_hash 也是 session_id(rfc 文档里面提到的 session_identifier)
        exchange_hash = self.do_hash(m.as_bytes())
        self.kex_result.H = exchange_hash
        # print("exchange_hash", exchange_hash)
        if not self.kex_result.session_id:
            self.kex_result.session_id = exchange_hash

        sig = self.host_key.get_sign(exchange_hash)
        # print("signature", sig)
        # print("================================\n\n")
        return sig

    def do_hash(self, b: bytes) -> bytes:
        return self.hash_call(b).digest()


class EcdhSha2Nistp384Kex(EcdhSha2Nistp256Kex):
    hash_call = hashlib.sha384
    curve_cls = ec.SECP384R1


class EcdhSha2Nistp521Kex(EcdhSha2Nistp256Kex):
    hash_call = hashlib.sha512
    curve_cls = ec.SECP521R1


def string_from_file(filepath: t.Union[str, pathlib.Path]) -> str:
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def bytes_from_file(filepath: t.Union[str, pathlib.Path]) -> bytes:
    with open(filepath, "rb") as f:
        return f.read()


def lines_from_file(filepath: t.Union[str, pathlib.Path]) -> t.List[str]:
    with open(filepath, "r", encoding="utf-8") as f:
        return list(f)


#################################
# 密钥交换 kex 支持
#################################
def get_dh_prime(
        generator: int,
        min_bits_of_prime: int,
        prefer_bits_of_prime: int,
        max_bits_of_prime: int,
) -> int:
    """获取 DH 算法可用的素数。
    临时生成太慢了，采用跟 openssh 一样的方式，从预先生成的素数中随机返回一个满足要求的。
    如果要自己生成，可参考下面的命令（生成 2048bits 素数）

    ssh-keygen -M generate -O bits=2048 moduli-2048.candidates
    ssh-keygen -M screen -f moduli-2048.candidates moduli-2048

    参考：https://manpages.ubuntu.com/manpages/focal/man1/ssh-keygen.1.html#moduli%20generation

    Args:
        generator: 算法中的底数 g ，一般是 2 或 5
        min_bits_of_prime: 素数 p 的最小比特数
        prefer_bits_of_prime: 素数 p 的比特数，优先采用
        max_bits_of_prime: 素数 p 的最大比特数

    Returns:
        可用的素数
    """
    MODULI_TESTS_COMPOSITE = 0x1
    # openssh 用的这个文件一般是 /etc/ssh/moduli
    moduli_filepath = SSH_DIR / "moduli"
    lines = lines_from_file(moduli_filepath)
    # 满足 prefer_bits_of_prime 条件的素数
    prefer_primes = []
    # 满足 min_bits_of_prime 和 max_bits_of_prime 条件的素数
    match_primes = []
    for line in lines:
        line = line.strip()
        if line.startswith("#"):
            # 跳过注释
            continue
        # 每行是一个素数，一行的元素按空格划分
        # 从左到右分别是
        #   时间 类型 测试类型 测试次数 比特数 十六进制generator 十六进制素数
        # https://man7.org/linux/man-pages/man5/moduli.5.html
        parts = line.split()
        if parts[1] != "2":
            continue
        test_flag = int(parts[2])
        if test_flag & MODULI_TESTS_COMPOSITE or test_flag == 0:
            continue
        trials = int(parts[3])
        if trials == 0:
            continue
        # 这个比特数从 0 开始，比如 2048 比特，这个值是 2047
        bits = int(parts[4]) + 1
        g = int(parts[5], 16)
        if g != generator:
            continue
        p = int(parts[6], 16)
        if bits == prefer_bits_of_prime:
            prefer_primes.append(p)
        elif min_bits_of_prime <= bits <= max_bits_of_prime:
            match_primes.append(p)
    if prefer_primes:
        return secrets.choice(prefer_primes)
    if match_primes:
        return secrets.choice(match_primes)

    raise ValueError("No prime numbers found that meet the requirements.")


class DiffieHellmanGroupExchangeSha256Kex(KeyExchangeInterface):
    """diffie-hellman-group-exchange-sha256

    rfc: https://www.rfc-editor.org/rfc/rfc4419
    """

    def __init__(self, transport: "SSHServerTransport", session_id: t.Optional[bytes]):
        self.transport = transport
        self.kex_result = KexResult(
            transport.side,
            self,
            b"",
            b"",
            b"",
        )
        if session_id:
            self.kex_result.session_id = session_id
        self.kex_result.kex = self
        self.host_key = self.transport.get_server_host_key()

        # 保存计算 exchange hash 需要的信息
        self._k_s = self.host_key.get_k_s()
        self._min_psize = None
        self._prefer_psize = None
        self._max_psize = None
        self._p = None
        self._g = None
        self._e = None
        self._f = None

        self._h = None

        self.private_key = None
        self.remote_public_key = None

    def do_server_exchange(self) -> "KexResult":
        # 客户端会先传输自己希望素数 p 有多少个 bit
        m = self.transport.read_message(SSHMessageID.KEX_DH_GEX_REQUEST)
        min_psize = m.get_uint32()
        prefer_psize = m.get_uint32()
        max_psize = m.get_uint32()
        self._min_psize = min_psize
        self._prefer_psize = prefer_psize
        self._max_psize = max_psize
        logger.debug(
            "SSH_MSG_KEX_DH_GEX_REQUEST(%s<%s<%s) received",
            min_psize,
            prefer_psize,
            max_psize,
        )
        if not (min_psize <= prefer_psize <= max_psize):
            raise DisconnectError(
                SSHDisconnectReasonID.KEY_EXCHANGE_FAILED,
                "invalid size in bits of an acceptable group",
            )
        # 生成服务端的参数
        # https://www.rfc-editor.org/rfc/rfc4419#section-6.1
        # generator 推荐使用 2
        server_generator = 2
        server_prime = get_dh_prime(
            server_generator, min_psize, prefer_psize, max_psize
        )
        server_pn = dh.DHParameterNumbers(server_prime, server_generator)
        server_parameters = server_pn.parameters()
        self.private_key = server_parameters.generate_private_key()
        self._p = server_prime
        self._g = server_generator

        group_msg = Message()
        group_msg.add_message_id(SSHMessageID.KEX_DH_GEX_GROUP)
        group_msg.add_mpint(server_prime)
        group_msg.add_mpint(server_generator)
        self.transport.write_message(group_msg)
        logger.debug("SSH_MSG_KEX_DH_GEX_GROUP sent")

        m = self.transport.read_message(SSHMessageID.KEX_DH_GEX_INIT)
        e = m.get_mpint()
        self._e = e
        client_pn = dh.DHPublicNumbers(e, server_pn)
        self.remote_public_key = client_pn.public_key()
        logger.debug("SSH_MSG_KEX_DH_GEX_INIT received")

        # 服务器响应
        #      byte    SSH_MSG_KEX_DH_GEX_REPLY
        #      string  server public host key and certificates (K_S)
        #      mpint   f
        #      string  signature of H
        reply_message = Message()
        reply_message.add_message_id(SSHMessageID.KEX_DH_GEX_REPLY)
        reply_message.add_string(self._k_s)
        f = self.private_key.public_key().public_numbers().y
        self._f = f
        reply_message.add_mpint(f)
        reply_message.add_string(self._get_signature_on_exchange_hash())
        self.transport.write_message(reply_message)
        logger.debug("SSH_MSG_KEX_DH_GEX_REPLY sent")
        return self.kex_result

    def do_client_exchange(self) -> "KexResult":
        pass

    def _get_shared_secret(self) -> bytes:
        k = self.private_key.exchange(self.remote_public_key)
        return k

    def _get_signature_on_exchange_hash(self):
        """the signature on the exchange hash

        The exchange hash H is computed as the hash of the concatenation of
        the following.

             string  V_C, the client's version string (CR and NL excluded)
             string  V_S, the server's version string (CR and NL excluded)
             string  I_C, the payload of the client's SSH_MSG_KEXINIT
             string  I_S, the payload of the server's SSH_MSG_KEXINIT
             string  K_S, the host key
             uint32  min, minimal size in bits of an acceptable group
             uint32  n, preferred size in bits of the group the server will send
             uint32  max, maximal size in bits of an acceptable group
             mpint   p, safe prime
             mpint   g, generator for subgroup
             mpint   e, exchange value sent by the client
             mpint   f, exchange value sent by the server
             mpint   K, the shared secret
        """
        # 计算共享密钥
        k = self._get_shared_secret()
        k = Message.bytes_to_mpint(k)
        self.kex_result.K = k

        # exchange hash
        m = Message()
        m.add_string(self.transport.client_version_data)
        m.add_string(self.transport.server_version_data)
        m.add_string(self.transport.client_algorithms_message.as_bytes())
        m.add_string(self.transport.server_algorithms_message.as_bytes())
        m.add_string(self._k_s)
        m.add_uint32(self._min_psize)
        m.add_uint32(self._prefer_psize)
        m.add_uint32(self._max_psize)
        m.add_mpint(self._p)
        m.add_mpint(self._g)
        m.add_mpint(self._e)
        m.add_mpint(self._f)
        m.add_raw_bytes(k)

        # 如果这是第一次密钥交换，那么这个 exchange_hash 也是 session_id(rfc 文档里面提到的 session_identifier)
        exchange_hash = self.do_hash(m.as_bytes())
        self.kex_result.H = exchange_hash
        if not self.kex_result.session_id:
            self.kex_result.session_id = exchange_hash

        sig = self.host_key.get_sign(exchange_hash)
        return sig

    def do_hash(self, b: bytes) -> bytes:
        return hashlib.sha256(b).digest()


class DiffieHellmanGroupExchangeSha1Kex(DiffieHellmanGroupExchangeSha256Kex):
    def do_hash(self, b: bytes) -> bytes:
        return hashlib.sha1(b).digest()


# diffie-hellman-groupx-shax 算法使用的参数
# 如 diffie-hellman-group16-sha512 使用 group16 的参数
# https://www.rfc-editor.org/rfc/rfc2409#section-6
# https://www.rfc-editor.org/rfc/rfc3526#section-2
oakley_groups = {
    "group1": {
        "generator": 2,
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
            16,
        ),
    },
    "group2": {
        "generator": 2,
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
            16,
        ),
    },
    "group5": {
        "generator": 2,
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
            16,
        ),
    },
    "group14": {
        "generator": 2,
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
            16,
        ),
    },
    "group15": {
        "generator": 2,
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
            16,
        ),
    },
    "group16": {
        "generator": 2,
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
            16,
        ),
    },
    "group17": {
        "generator": 2,
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF",
            16,
        ),
    },
    "group18": {
        "generator": 2,
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF",
            16,
        ),
    },
}


class DiffieHellmanGroup16Sha512Kex(KeyExchangeInterface):
    """diffie-hellman-group16-sha512

    ref: https://www.rfc-editor.org/rfc/rfc4253#section-8
    """

    hash_call = hashlib.sha512
    group = "group16"

    def __init__(self, transport: "SSHServerTransport", session_id: t.Optional[bytes]):
        self.transport = transport
        self.kex_result = KexResult(
            transport.side,
            self,
            b"",
            b"",
            b"",
        )
        if session_id:
            self.kex_result.session_id = session_id
        self.kex_result.kex = self
        self.host_key = self.transport.get_server_host_key()

        # 计算 exchange hash 所需信息
        self._k_s = self.host_key.get_k_s()
        self._e = None
        self._f = None

        self.private_key = None
        self.remote_public_key = None

    def do_server_exchange(self) -> "KexResult":
        # 生成服务器参数
        group = oakley_groups[self.group]
        server_pn = dh.DHParameterNumbers(group["prime"], group["generator"])
        server_parameters = server_pn.parameters()
        self.private_key = server_parameters.generate_private_key()

        #    First, the client sends the following:
        #       byte      SSH_MSG_KEXDH_INIT
        #       mpint     e
        m = self.transport.read_message(SSHMessageID.KEXDH_INIT)
        e = m.get_mpint()
        self._e = e
        client_pn = dh.DHPublicNumbers(e, server_pn)
        self.remote_public_key = client_pn.public_key()
        logger.debug("SSH_MSG_KEXDH_INIT received")
        reply_msg = Message()
        reply_msg.add_message_id(SSHMessageID.KEXDH_REPLY)
        reply_msg.add_string(self._k_s)
        f = self.private_key.public_key().public_numbers().y
        self._f = f
        reply_msg.add_mpint(f)
        reply_msg.add_string(self._get_signature_on_exchange_hash())
        self.transport.write_message(reply_msg)
        logger.debug("SSH_MSG_KEXDH_REPLY sent")
        return self.kex_result

    def do_client_exchange(self) -> "KexResult":
        pass

    def _get_shared_secret(self) -> bytes:
        k = self.private_key.exchange(self.remote_public_key)
        return k

    def _get_signature_on_exchange_hash(self):
        """the signature on the exchange hash

        The exchange hash H is computed as the hash of the concatenation of
        the following.

          string    V_C, the client's identification string (CR and LF
                    excluded)
          string    V_S, the server's identification string (CR and LF
                    excluded)
          string    I_C, the payload of the client's SSH_MSG_KEXINIT
          string    I_S, the payload of the server's SSH_MSG_KEXINIT
          string    K_S, the host key
          mpint     e, exchange value sent by the client
          mpint     f, exchange value sent by the server
          mpint     K, the shared secret
        """
        # 计算共享密钥
        k = self._get_shared_secret()
        k = Message.bytes_to_mpint(k)
        self.kex_result.K = k

        # exchange hash
        m = Message()
        m.add_string(self.transport.client_version_data)
        m.add_string(self.transport.server_version_data)
        m.add_string(self.transport.client_algorithms_message.as_bytes())
        m.add_string(self.transport.server_algorithms_message.as_bytes())
        m.add_string(self._k_s)
        m.add_mpint(self._e)
        m.add_mpint(self._f)
        m.add_raw_bytes(k)

        # 如果这是第一次密钥交换，那么这个 exchange_hash 也是 session_id(rfc 文档里面提到的 session_identifier)
        exchange_hash = self.do_hash(m.as_bytes())
        self.kex_result.H = exchange_hash
        if not self.kex_result.session_id:
            self.kex_result.session_id = exchange_hash

        sig = self.host_key.get_sign(exchange_hash)
        return sig

    def do_hash(self, b: bytes) -> bytes:
        return self.hash_call(b).digest()


class DiffieHellmanGroup18Sha512Kex(DiffieHellmanGroup16Sha512Kex):
    hash_call = hashlib.sha512
    group = "group18"


class DiffieHellmanGroup14Sha256Kex(DiffieHellmanGroup16Sha512Kex):
    hash_call = hashlib.sha256
    group = "group14"


class DiffieHellmanGroup14Sha1Kex(DiffieHellmanGroup16Sha512Kex):
    hash_call = hashlib.sha1
    group = "group14"


class DiffieHellmanGroup1Sha1Kex(DiffieHellmanGroup16Sha512Kex):
    hash_call = hashlib.sha1
    group = "group1"


def get_kex_obj(algo_name: str) -> t.Type["KeyExchangeInterface"]:
    """根据算法名字获取对应的实现。"""
    mapping = {
        "curve25519-sha256": Curve25519Sha256Kex,
        "curve25519-sha256@libssh.org": Curve25519Sha256Kex,
        "ecdh-sha2-nistp256": EcdhSha2Nistp256Kex,
        "ecdh-sha2-nistp384": EcdhSha2Nistp384Kex,
        "ecdh-sha2-nistp521": EcdhSha2Nistp521Kex,
        "diffie-hellman-group-exchange-sha256": DiffieHellmanGroupExchangeSha256Kex,
        "diffie-hellman-group-exchange-sha1": DiffieHellmanGroupExchangeSha1Kex,
        "diffie-hellman-group16-sha512": DiffieHellmanGroup16Sha512Kex,
        "diffie-hellman-group18-sha512": DiffieHellmanGroup18Sha512Kex,
        "diffie-hellman-group14-sha256": DiffieHellmanGroup14Sha256Kex,
        "diffie-hellman-group14-sha1": DiffieHellmanGroup14Sha1Kex,
        "diffie-hellman-group1-sha1": DiffieHellmanGroup1Sha1Kex,
    }
    return mapping[algo_name]


#################################
# 服务器 host key 支持
#################################
class ServerHostKeyBase(abc.ABC):
    """代表服务器的密钥"""

    algo = ""

    @abc.abstractmethod
    def get_sign(self, data: bytes) -> bytes:
        """对数据进行签名"""
        raise NotImplementedError("get_sign")

    @abc.abstractmethod
    def get_k_s(self) -> bytes:
        """返回用于密钥交换部分的 K_S"""
        raise NotImplementedError("get_public_key")


class EcdsaSha2Nistp256HostKey(ServerHostKeyBase):
    """ecdsa-sha2-nistp256 算法
    https://datatracker.ietf.org/doc/html/rfc5656
    """

    algo = "ecdsa-sha2-nistp256"
    category = "nistp256"

    def __init__(self, public_key_data: bytes, private_key_data: bytes):
        self.public_key = serialization.load_ssh_public_key(public_key_data)
        self.private_key = serialization.load_ssh_private_key(private_key_data, None)

    def get_k_s(self) -> bytes:
        # 下面这些结构格式都是抓包来的，长度都是大端序的 4 个字节
        # Host key type length: 19
        # Host key type: ecdsa-sha2-nistp256
        # ECDSA elliptic curve identifier length: 8
        # ECDSA elliptic curve identifier: nistp256
        # ECDSA public key length: 65
        # ECDSA public key (Q)
        # 找到了描述这个结构的文档 https://datatracker.ietf.org/doc/html/rfc5656#section-3.1
        raw_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        m = Message()
        m.add_string(self.algo.encode())
        m.add_string(self.category.encode())
        m.add_string(raw_key)
        b = m.as_bytes()
        return b

    def get_sign(self, data: bytes) -> bytes:
        sig = self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256()),
        )
        # 签名数据结构
        # https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2
        r, s = decode_dss_signature(sig)
        rs_m = Message()
        rs_m.add_mpint(r)
        rs_m.add_mpint(s)

        # wireshark 抓包拿到的数据结构
        # Host signature length
        # Host signature type length: 19
        # Host signature type: ecdsa-sha2-nistp256
        # 签名数据
        sig_m = Message()
        sig_m.add_string(self.algo.encode())
        sig_m.add_string(rs_m.as_bytes())
        sig_b = sig_m.as_bytes()
        return sig_b


class SSHEd25519HostKey(ServerHostKeyBase):
    """ssh-ed25519 算法
    https://www.rfc-editor.org/rfc/rfc8709
    """

    algo = "ssh-ed25519"

    def __init__(self, public_key_data: bytes, private_key_data: bytes):
        self.public_key = serialization.load_ssh_public_key(public_key_data)
        self.private_key = serialization.load_ssh_private_key(private_key_data, None)

    def get_k_s(self) -> bytes:
        # https://www.rfc-editor.org/rfc/rfc8709#section-4
        # 结构如下
        #   string "ssh-ed25519"
        #   string key
        raw_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        m = Message()
        m.add_string(self.algo.encode())
        m.add_string(raw_key)
        b = m.as_bytes()
        return b

    def get_sign(self, data: bytes) -> bytes:
        # https://www.rfc-editor.org/rfc/rfc8709#section-6
        # 结构如下
        #   string "ssh-ed25519"
        #   string signature
        sig = self.private_key.sign(
            data,
        )
        m = Message()
        m.add_string(self.algo.encode())
        m.add_string(sig)
        return m.as_bytes()


class SSHRsaHostKey(ServerHostKeyBase):
    """ssh-rsa
    https://www.rfc-editor.org/rfc/rfc4253#section-6.6
    """

    algo = "ssh-rsa"
    hashes_cls = hashes.SHA1

    def __init__(self, public_key_data: bytes, private_key_data: bytes):
        self.public_key: rsa.RSAPublicKey = serialization.load_ssh_public_key(
            public_key_data
        )
        self.private_key: rsa.RSAPrivateKey = serialization.load_ssh_private_key(
            private_key_data, None
        )

    def get_k_s(self) -> bytes:
        # https://www.rfc-editor.org/rfc/rfc4253#section-6.6
        # 结构如下
        #   string    "ssh-rsa"
        #   mpint     e
        #   mpint     n
        pn = self.public_key.public_numbers()
        m = Message()
        m.add_string(self.algo.encode())
        m.add_mpint(pn.e)
        m.add_mpint(pn.n)
        b = m.as_bytes()
        return b
        pass

    def get_sign(self, data: bytes) -> bytes:
        # https://www.rfc-editor.org/rfc/rfc4253#section-6.6
        # 结构如下
        #       string    "ssh-rsa"
        #       string    rsa_signature_blob
        sig = self.private_key.sign(
            data,
            PKCS1v15(),
            self.hashes_cls(),
        )

        sig_m = Message()
        sig_m.add_string(self.algo.encode())
        sig_m.add_string(sig)
        sig_b = sig_m.as_bytes()
        return sig_b
        pass


class SSHRsaSha256HostKey(SSHRsaHostKey):
    """rsa-sha2-256
    https://www.rfc-editor.org/rfc/rfc8332
    """

    algo = "rsa-sha2-256"
    hashes_cls = hashes.SHA256


class SSHRsaSha512HostKey(SSHRsaHostKey):
    """rsa-sha2-512
    https://www.rfc-editor.org/rfc/rfc8332
    """

    algo = "rsa-sha2-512"
    hashes_cls = hashes.SHA512


class SSHDssHostKey(ServerHostKeyBase):
    """ssh-dss
    说明见 https://www.rfc-editor.org/rfc/rfc4253#section-6.6
    """

    algo = "ssh-rsa"
    hashes_cls = hashes.SHA1

    def __init__(self, public_key_data: bytes, private_key_data: bytes):
        self.public_key: dsa.DSAPublicKey = serialization.load_ssh_public_key(
            public_key_data
        )
        self.private_key: dsa.DSAPrivateKey = serialization.load_ssh_private_key(
            private_key_data, None
        )

    def get_k_s(self) -> bytes:
        # 结构如下
        #       string    "ssh-dss"
        #       mpint     p
        #       mpint     q
        #       mpint     g
        #       mpint     y
        param_n = self.public_key.parameters().parameter_numbers()
        pn = self.public_key.public_numbers()
        m = Message()
        m.add_string(self.algo.encode())
        m.add_mpint(param_n.p)
        m.add_mpint(param_n.q)
        m.add_mpint(param_n.g)
        m.add_mpint(pn.y)
        return m.as_bytes()

    def get_sign(self, data: bytes) -> bytes:
        # 结构如下
        #       string    "ssh-dss"
        #       string    dss_signature_blob
        sig = self.private_key.sign(
            data,
            hashes.SHA1(),
        )
        m = Message()
        m.add_string(self.algo.encode())
        m.add_string(sig)
        return m.as_bytes()
        pass


#################################
# 消息 mac 支持
#################################
class MacInterface(abc.ABC):
    length = 0
    key_size = 0
    is_etm = False

    @abc.abstractmethod
    def verify(self, key: bytes, message: bytes, mac: bytes) -> bool:
        raise NotImplementedError("verify")

    @abc.abstractmethod
    def calculate(self, key: bytes, message: bytes) -> bytes:
        raise NotImplementedError("calculate")


class HmacImpl(MacInterface):
    hash_cls = None

    def verify(self, key: bytes, message: bytes, mac: bytes) -> bool:
        got = hmac.HMAC(key, message, self.hash_cls).digest()
        return secrets.compare_digest(got, mac)

    def calculate(self, key: bytes, message: bytes) -> bytes:
        got = hmac.HMAC(key, message, self.hash_cls).digest()
        return got


class HmacSha256Impl(HmacImpl):
    length = 32
    key_size = 32
    hash_cls = hashlib.sha256
    is_etm = False


class HmacSha256EtmImpl(HmacSha256Impl):
    is_etm = True


class HmacSha512Impl(HmacImpl):
    length = 64
    key_size = 64
    hash_cls = hashlib.sha512
    is_etm = False


class HmacSha512EtmImpl(HmacSha512Impl):
    is_etm = True


class HmacSha1Impl(HmacImpl):
    length = 20
    key_size = 20
    hash_cls = hashlib.sha1


class HmacSha1EtmImpl(HmacSha1Impl):
    is_etm = True


def get_mac_impl(algo: str) -> t.Type["MacInterface"]:
    mapping = {
        "hmac-sha2-256-etm@openssh.com": HmacSha256EtmImpl,
        "hmac-sha2-512-etm@openssh.com": HmacSha512EtmImpl,
        "hmac-sha1-etm@openssh.com": HmacSha1EtmImpl,
        "hmac-sha2-256": HmacSha256Impl,
        "hmac-sha2-512": HmacSha512Impl,
        "hmac-sha1": HmacSha1Impl,
    }
    return mapping[algo]


#################################
# packet 读写支持，包含加解密、 mac 等处理
#################################
class PacketIOInterface(abc.ABC):
    """SSH packet 格式的读写接口
    格式可看 https://datatracker.ietf.org/doc/html/rfc4253#section-6

    uint32    packet_length
    byte      padding_length
    byte[n1]  payload; n1 = packet_length - padding_length - 1
    byte[n2]  random padding; n2 = padding_length
    byte[m]   mac (Message Authentication Code - MAC); m = mac_length

    补充说明：packet_length 是大端序编码， mac 长度需要根据使用的算法确定，初始时 mac 长度为 0
    """

    # 读写 packet 编号，从 0 开始计数
    read_seq_num: int
    write_seq_num: int

    @abc.abstractmethod
    def read_packet(self) -> bytes:
        raise NotImplementedError("read_packet")

    @abc.abstractmethod
    def write_packet(self, payload: bytes):
        raise NotImplementedError("write_packet")


# https://www.rfc-editor.org/rfc/rfc4253#section-7.2
# 输出密钥等需要的字符，就是上面链接提到的 A B C D E F
class CipherTag(t.NamedTuple):
    iv_tag: bytes
    key_tag: bytes
    mac_tag: bytes


# client to server, client 加密信息所需
client_tag = CipherTag(
    b"A",
    b"C",
    b"E",
)
# server to client, server 加密信息所需
server_tag = CipherTag(
    b"B",
    b"D",
    b"F",
)


class RawPacketIO(PacketIOInterface):
    # 从 go golang.org/x/crypto/ssh/cipher.go copy
    # 下面这段也是 go 代码里面原本的注释
    # 	// RFC 4253 section 6.1 defines a minimum packet size of 32768 that implementations
    # 	// MUST be able to process (plus a few more kilobytes for padding and mac). The RFC
    # 	// indicates implementations SHOULD be able to handle larger packet sizes, but then
    # 	// waffles on about reasonable limits.
    # 	//
    # 	// OpenSSH caps their maxPacket at 256kB so we choose to do
    # 	// the same. maxPacket is also used to ensure that uint32
    # 	// length fields do not overflow, so it should remain well
    # 	// below 4G.
    max_packet = 256 * 1024

    read_timeout = 60

    def __init__(self, sock: socket.socket, write_seq_num: int, read_seq_num: int):
        self._sock = sock
        # 读写数据大小（单位：字节）
        self._read_size = 0
        self._write_size = 0

        # 读写 packet 编号，从 0 开始计数
        self.read_seq_num = write_seq_num
        self.write_seq_num = read_seq_num

    def _read_full(self, n: int) -> bytes:
        """
        读满 n 字节数据
        """
        # 每次 recv 和 send 都需要重新设置 timeout
        # 一次设置只影响一次 recv/send 调用
        self._sock.settimeout(self.read_timeout)
        b = self._sock.recv(n)
        if b == b"":
            raise BadRequestError("remote closed connection")
        if len(b) != n:
            raise BadRequestError(f"can not read {n} size data")
        self._read_size += len(b)
        return b

    def _read(self, n: int) -> bytes:
        """
        读取最多 n 字节数据
        """
        self._sock.settimeout(self.read_timeout)
        b = self._sock.recv(n)
        self._read_size += len(b)
        return b

    def _write(self, b: bytes) -> int:
        """
        写入数据
        """
        self._sock.settimeout(self.read_timeout)
        self._sock.sendall(b)
        self._write_size += len(b)
        return len(b)

    def read_packet(self) -> bytes:
        """
        读取 packet ，格式如下
            uint32    packet_length
            byte      padding_length
            byte[n1]  payload; n1 = packet_length - padding_length - 1
            byte[n2]  random padding; n2 = padding_length
            byte[m]   mac (Message Authentication Code - MAC); m = mac_length
        """
        self.read_seq_num += 1
        b = self._read_full(4)
        packet_length = int.from_bytes(b, "big")
        if packet_length > self.max_packet:
            raise PacketTooLargeError(f"packet too large: {packet_length}")
        b = self._read_full(1)
        padding_length = int.from_bytes(b, "big")
        payload = self._read_full(packet_length - padding_length - 1)
        padding = self._read_full(padding_length)
        # no mac ，在数据加密传输后才会有 mac 这部分数据
        return payload

    def write_packet(self, payload: bytes):
        """
        写入 packet ，格式如下
            uint32    packet_length
            byte      padding_length
            byte[n1]  payload; n1 = packet_length - padding_length - 1
            byte[n2]  random padding; n2 = padding_length
            byte[m]   mac (Message Authentication Code - MAC); m = mac_length

        packet_length + padding_length + payload + random padding
        这上面四部分连起来大小需要是 8 的整数倍
        """
        self.write_seq_num += 1
        block_size = 8
        # 没有在 rfc4253 中找到 padding 最小长度的要求
        # 但是在 openssh 的代码注释里面搜索到最小长度的要求
        # https://github.com/openssh/openssh-portable/blob/master/packet.c#LL1125
        # minimum padding is 4 bytes
        padding_length = block_size - (len(payload) + 5) % block_size
        if padding_length < 4:
            padding_length += block_size
        packet_length = len(payload) + 1 + padding_length
        buffer = [
            packet_length.to_bytes(4, "big"),
            padding_length.to_bytes(1, "big"),
            payload,
            secrets.token_bytes(padding_length),
        ]
        packet = b"".join(buffer)
        self._write(packet)


class Chacha20Poly1305PacketIO(RawPacketIO):
    """

    openssh 对 chacha20-poly1305 的说明
    https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.chacha20poly1305
    分成两个 key ，一个用来加密 packet 长度，一个加密数据
    """

    def __init__(
            self,
            sock: socket.socket,
            write_seq_num: int,
            read_seq_num: int,
            kex_result: KexResult,
            cipher_tag: "CipherTag",
    ):
        super().__init__(sock, write_seq_num, read_seq_num)

        self._kex_result = kex_result

        key = self._kex_result.compute_key(64, cipher_tag.key_tag)

        self._length_key = key[32:]
        self._data_key = key[:32]

    def read_packet(self) -> bytes:
        self.read_seq_num += 1
        # 先解密长度
        b = self._read_full(4)
        nonce = b"\x00" * 8 + struct.pack(">Q", self.read_seq_num)
        algorithm = algorithms.ChaCha20(self._length_key, nonce)
        cipher = Cipher(algorithm, mode=None)
        # encryptor = cipher.encryptor()
        # ct = encryptor.update(b"a secret message")
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(b)
        print("length", int.from_bytes(decrypted, "big"))
        packet_length = int.from_bytes(decrypted, "big")

        payload = self._read_full(packet_length)
        # mac 验证
        mac = self._read_full(16)
        algorithm = algorithms.ChaCha20(self._data_key, nonce)
        payload_cipher = Cipher(algorithm, mode=None)
        payload_encryptor = payload_cipher.encryptor()
        poly_key = payload_encryptor.update(b"\0" * 32)
        p = poly1305.Poly1305(poly_key)
        p.update(b + payload)
        p.verify(mac)
        # 解密数据
        nonce = b"\1" + b"\0" * 7 + struct.pack(">Q", self.read_seq_num)
        algorithm = algorithms.ChaCha20(self._data_key, nonce)
        payload_cipher = Cipher(algorithm, mode=None)
        payload_decryptor = payload_cipher.decryptor()
        decrypted = payload_decryptor.update(payload)
        print("decrypted", decrypted, len(decrypted))
        padding_length = decrypted[0]
        return decrypted[1:-padding_length]

    def write_packet(self, payload: bytes):
        self.write_seq_num += 1
        print("write_seq_num", self.write_seq_num, len(payload), payload)
        # 计算 packet 长度和 padding 长度
        block_size = 8
        # 这里计算 padding_length 的时候，没有算 packet_length 的 4 字节
        # 跟 https://datatracker.ietf.org/doc/html/rfc4253#section-6 不一样
        padding_length = block_size - (len(payload) + 1) % block_size
        if padding_length < 4:
            padding_length += block_size

        buffer = []
        # 加密 packet 长度
        packet_length = len(payload) + 1 + padding_length
        length_data = packet_length.to_bytes(4, "big")
        nonce = b"\x00" * 8 + struct.pack(">Q", self.write_seq_num)
        algorithm = algorithms.ChaCha20(self._length_key, nonce)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        ct = encryptor.update(length_data)
        buffer.append(ct)
        # 加密 packet 数据
        packet_data = (
                padding_length.to_bytes(1, "big")
                + payload
                + secrets.token_bytes(padding_length)
        )
        nonce = b"\1" + b"\0" * 7 + struct.pack(">Q", self.write_seq_num)
        algorithm = algorithms.ChaCha20(self._data_key, nonce)
        data_cipher = Cipher(algorithm, mode=None)
        data_encryptor = data_cipher.encryptor()
        et = data_encryptor.update(packet_data)
        buffer.append(et)
        # 计算 MAC
        nonce = b"\x00" * 8 + struct.pack(">Q", self.write_seq_num)
        algorithm = algorithms.ChaCha20(self._data_key, nonce)
        payload_cipher = Cipher(algorithm, mode=None)
        payload_encryptor = payload_cipher.encryptor()
        poly_key = payload_encryptor.update(b"\0" * 32)
        p = poly1305.Poly1305(poly_key)
        p.update(b"".join(buffer))
        mac = p.finalize()
        buffer.append(mac)
        packet = b"".join(buffer)
        self._write(packet)


class AESCtrCipherPacketIO(RawPacketIO):
    """https://datatracker.ietf.org/doc/html/rfc4344"""

    key_size = -1
    block_size = -1
    cipher_algo = algorithms.AES

    def __init__(
            self,
            sock: socket.socket,
            write_seq_num: int,
            read_seq_num: int,
            kex_result: "KexResult",
            mac_impl: "MacInterface",
            cipher_tag: "CipherTag",
    ):
        super().__init__(sock, write_seq_num, read_seq_num)

        self._kex_result = kex_result
        self.mac_impl = mac_impl

        self._iv = b""
        self._key = b""
        self._mac_key = b""

        self._iv = self._kex_result.compute_key(self.block_size, cipher_tag.iv_tag)
        self._key = self._kex_result.compute_key(self.key_size, cipher_tag.key_tag)
        self._mac_key = self._kex_result.compute_key(
            self.mac_impl.key_size, cipher_tag.mac_tag
        )

    def read_packet(self) -> bytes:
        self.read_seq_num += 1
        seq_bytes = self.read_seq_num.to_bytes(4, "big")
        length_bytes = self._read_full(4)
        if self.mac_impl.is_etm:
            # 长度是明文
            packet_length = int.from_bytes(length_bytes, "big")
            print("packet length", packet_length)
            if packet_length > self.max_packet:
                raise PacketTooLargeError(f"packet too large: {packet_length}")
            ciphertext = self._read_full(packet_length)
            mac = self._read_full(self.mac_impl.length)
            if not self.mac_impl.verify(
                    self._mac_key, seq_bytes + length_bytes + ciphertext, mac
            ):
                raise DisconnectError(
                    SSHDisconnectReasonID.MAC_ERROR,
                )
            cipher = Cipher(self.cipher_algo(self._key), modes.CTR(self._iv))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            # 长度是密文
            cipher = Cipher(self.cipher_algo(self._key), modes.CTR(self._iv))
            decryptor = cipher.decryptor()
            decrypted_length_bytes = decryptor.update(length_bytes)
            packet_length = int.from_bytes(decrypted_length_bytes, "big")
            print("packet length", packet_length)
            if packet_length > self.max_packet:
                raise PacketTooLargeError(f"packet too large: {packet_length}")
            ciphertext = self._read_full(packet_length)
            mac = self._read_full(self.mac_impl.length)
            # cipher = Cipher(algorithms.AES128(self._read_key), modes.CTR(self._read_iv))
            # decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            if not self.mac_impl.verify(
                    self._mac_key, seq_bytes + decrypted_length_bytes + plaintext, mac
            ):
                print(
                    "invalid mac", mac, seq_bytes + decrypted_length_bytes + plaintext
                )
                raise DisconnectError(
                    SSHDisconnectReasonID.MAC_ERROR,
                )
        padding_length = plaintext[0]
        print("padding_length", plaintext[0])
        payload = plaintext[1:-padding_length]
        print("payload", payload)
        return payload

    def write_packet(self, payload: bytes):
        self.write_seq_num += 1
        print("write_seq_num", self.write_seq_num, len(payload), payload)
        seq_bytes = self.write_seq_num.to_bytes(4, "big")
        block_size = self.block_size
        if self.mac_impl.is_etm:
            # 计算 packet 长度和 padding 长度
            # 最前面 4 字节的 packet_length 不算
            # 综合这些例子，应该是按加密的数据来算 padding ，这里长度没有加密，所以没有算在里面
            padding_length = block_size - (len(payload) + 1) % block_size
            if padding_length < 4:
                padding_length += block_size
            packet_length = len(payload) + 1 + padding_length
            length_bytes = packet_length.to_bytes(4, "big")
            # 加密数据
            buffer = [
                padding_length.to_bytes(1, "big"),
                payload,
                secrets.token_bytes(padding_length),
            ]
            plaintext = b"".join(buffer)
            cipher = Cipher(self.cipher_algo(self._key), modes.CTR(self._iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            # 计算加密数据的 mac
            mac = self.mac_impl.calculate(
                self._mac_key,
                seq_bytes + length_bytes + ciphertext,
            )
            packet = b"".join(
                [
                    length_bytes,
                    ciphertext,
                    mac,
                ]
            )
        else:
            # 计算 packet 长度和 padding 长度
            padding_length = block_size - (len(payload) + 5) % block_size
            if padding_length < 4:
                padding_length += block_size
            packet_length = len(payload) + 1 + padding_length
            length_bytes = packet_length.to_bytes(4, "big")
            # 加密数据，长度也要加密
            buffer = [
                length_bytes,
                padding_length.to_bytes(1, "big"),
                payload,
                secrets.token_bytes(padding_length),
            ]
            plaintext = b"".join(buffer)
            cipher = Cipher(self.cipher_algo(self._key), modes.CTR(self._iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            # 计算原始数据的 mac
            mac = self.mac_impl.calculate(
                self._mac_key,
                seq_bytes + plaintext,
            )
            packet = b"".join(
                [
                    ciphertext,
                    mac,
                ]
            )
        self._write(packet)


class AES128CtrCipherPacketIO(AESCtrCipherPacketIO):
    key_size = 16
    block_size = 16
    cipher_algo = algorithms.AES128


class AES192CtrCipherPacketIO(AESCtrCipherPacketIO):
    key_size = 24
    block_size = 16
    # 这里用的是 algorithms.AES
    # 他支持 192 ，但是不像 AES128 这样，没有特定的 AES192
    cipher_algo = algorithms.AES


class AES256CtrCipherPacketIO(AESCtrCipherPacketIO):
    key_size = 32
    block_size = 16
    cipher_algo = algorithms.AES256


class AESGCMCipherPacketIO(RawPacketIO):
    """https://www.rfc-editor.org/rfc/rfc5647
    AES-GCM 自带 mac 功能，不再需要额外的 mac 计算
    """

    key_size = -1
    block_size = -1
    iv_size = 12
    tag_size = 16
    pass

    def __init__(
            self,
            sock: socket.socket,
            write_seq_num: int,
            read_seq_num: int,
            kex_result: "KexResult",
            cipher_tag: "CipherTag",
    ):
        super().__init__(sock, write_seq_num, read_seq_num)

        self._kex_result = kex_result

        self._iv = kex_result.compute_key(self.iv_size, cipher_tag.iv_tag)
        self._key = kex_result.compute_key(self.key_size, cipher_tag.key_tag)

    def _inc_iv(self):
        # https://www.rfc-editor.org/rfc/rfc5647#section-7.1
        # iv 12 字节，将后面 8 字节当做 64 位整数，每次加解密后都加一
        iv = self._iv
        prefix = iv[:4]
        invocation_counter = int.from_bytes(iv[4:], "big")
        invocation_counter = (invocation_counter + 1) & 0xFFFFFFFFFFFFFFFF
        self._iv = prefix + invocation_counter.to_bytes(8, "big")

    def read_packet(self) -> bytes:
        self.read_seq_num += 1

        length_bytes = self._read_full(4)
        packet_length = int.from_bytes(length_bytes, "big")
        print("packet length", packet_length)
        if packet_length > self.max_packet:
            raise PacketTooLargeError(f"packet too large: {packet_length}")

        ciphertext = self._read_full(packet_length + self.tag_size)
        aesgcm = AESGCM(self._key)
        plaintext = aesgcm.decrypt(self._iv, ciphertext, length_bytes)
        padding_length = plaintext[0]
        print("plaintext", plaintext)
        payload = plaintext[1:-padding_length]
        print("payload", payload)
        self._inc_iv()
        return payload

    def write_packet(self, payload: bytes):
        self.write_seq_num += 1
        block_size = self.block_size
        # https://www.rfc-editor.org/rfc/rfc5647#section-5.2
        # 4 <= padding_length < 256
        # 因为 4 字节的 packet_length 长度数据没有加密，所以这里不算 4 个字节
        padding_length = block_size - (len(payload) + 1) % block_size
        if padding_length < 4:
            padding_length += block_size
        packet_length = len(payload) + 1 + padding_length
        if packet_length > self.max_packet:
            raise PacketTooLargeError(f"packet too large: {packet_length}")
        length_bytes = packet_length.to_bytes(4, "big")
        buffer = [
            padding_length.to_bytes(1, "big"),
            payload,
            secrets.token_bytes(padding_length),
        ]
        plaintext = b"".join(buffer)
        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(self._iv, plaintext, length_bytes)
        self._inc_iv()
        packet = length_bytes + ciphertext
        self._write(packet)


class AES128GCMCipherPacketIO(AESGCMCipherPacketIO):
    key_size = 16
    block_size = 16


class AES256GCMCipherPacketIO(AESGCMCipherPacketIO):
    key_size = 32
    block_size = 16


#################################
# transport 支持
#################################
class SSHServerTransport:
    """
    The Secure Shell (SSH) Transport Layer Protocol: https://datatracker.ietf.org/doc/html/rfc4253

    实现 server 端 SSH 传输层
    """

    # 这里的算法列表都是 copy 的 openssh 客户端发送的算法
    # 算法名称中的一些缩写解释
    #   nist 美国国家标准与技术研究院，代表着算法由其标准化
    #   nistp256 代表的使用的椭圆曲线类别，其他的 nistp384 等等同理
    #   curve25519 是另外一种椭圆曲线类别
    #   ec 表示椭圆曲线（英文 elliptic curve ）
    #   dh 表示 diffie-hellman 密钥交换算法
    #   sha2 算法名称中间的这个表示使用 sha2 哈希算法
    #   @xxx @ 符号表示这个算法由组织 xxx 实现，没有 @ 的都是标准算法名字
    #   cert-v01 表示这个 key 是一个证书，有数字签名验证（类似 https 使用的证书）
    kex_algorithms = (
        # "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        # "ecdh-sha2-nistp256",
        # "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        # "diffie-hellman-group16-sha512",
        # "diffie-hellman-group18-sha512",
        # "diffie-hellman-group14-sha256",
        # 下面三个不推荐使用
        # "diffie-hellman-group14-sha1",
        # "diffie-hellman-group1-sha1",
        # "diffie-hellman-group-exchange-sha1",
        # 这个 ext-info-c 是表示扩展的意思，我们暂时不管
        # 'ext-info-c',
    )
    support_server_host_key_algorithms = (
        # 这些用证书的全部注释，没有证书
        # "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        # "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        # "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        # "ssh-ed25519-cert-v01@openssh.com",
        # "rsa-sha2-512-cert-v01@openssh.com",
        # "rsa-sha2-256-cert-v01@openssh.com",
        # "ssh-rsa-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256",
        # "ecdsa-sha2-nistp384",
        # "ecdsa-sha2-nistp521",
        "ssh-ed25519",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
        # "ssh-dss",
    )
    encryption_algorithms = (
        # "chacha20-poly1305@openssh.com",
        # "aes128-ctr",
        # "aes192-ctr",
        # "aes256-ctr",
        # "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    )

    # 自带数据完整性验证的加密算法，不需要 mac 算法和运算
    aead_encryption_algorithms = (
        "chacha20-poly1305@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    )

    mac_algorithms = (
        # umac 没在网上搜到什么资料，不知道用 Python 怎么实现
        # etm 表示先加密再对加密数据计算 MAC
        # "umac-64-etm@openssh.com",
        # "umac-128-etm@openssh.com",
        # "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        # "hmac-sha1-etm@openssh.com",
        # "umac-64@openssh.com",
        # "umac-128@openssh.com",
        # "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
    )
    compression_algorithms = ("none", "zlib@openssh.com", "zlib")
    languages = ()

    # 授权超时时间（秒）
    authentication_timeout = 10 * 60
    # 授权最大尝试次数
    authentication_max_attempts = 20

    def __init__(self, sock: socket.socket):
        self._sock = sock

        # 经过测试发现这种方式可以很好地支持 readline ，可以应对客户端不同的数据长度
        self._rfile = self._sock.makefile("rb", -1)

        self.side = SSHSide.server

        self.server_host_key_algorithms: t.Tuple[str] = ()
        self.server_host_keys: t.Dict[str, ServerHostKeyBase] = {}

        # 双方交换协议版本的数据需要保存，后面有用
        self.server_version_data = b"SSH-2.0-boatland_0.1"
        self.client_version_data = b""
        # 双方交换算法的数据也需要保存
        self.server_algorithms_message: Message = Message()
        self.client_algorithms_message: Message = Message()

        # 协商后采用的算法
        self._adopted_algo = AdoptedAlgorithm()

        self.kex_result: t.Optional["KexResult"] = None
        self.session_id = b""

        # read_seq_num write_seq_num 从 0 开始计数，所以传 -1 方便增加
        self._packet_reader: PacketIOInterface = RawPacketIO(self._sock, -1, -1)
        self._packet_writer: PacketIOInterface = self._packet_reader

        self.auth_username = ""
        self.auth_service_name = ""

    def start(self):
        self.side = SSHSide.server
        try:
            self._work()
        except DisconnectError as e:
            self.disconnect(e.reason_id, e.description)

    def _work(self):
        self.setup_server()
        self.exchange_protocol_version()
        self.negotiate_algorithm()
        self.exchange_key()

        m = self.read_message(SSHMessageID.SERVICE_REQUEST)
        service = m.get_string()
        if service not in (b"ssh-userauth", b"ssh-connection"):
            raise DisconnectError(
                SSHDisconnectReasonID.SERVICE_NOT_AVAILABLE,
                "unsupported service " + service.decode(),
            )

        m = Message()
        m.add_message_id(SSHMessageID.SERVICE_ACCEPT)
        m.add_string(service)
        self.write_message(m)

        if service == b"ssh-userauth":
            self.serve_userauth()
            m = self.read_message()
            print(m.as_bytes())
        else:
            self.serve_connection()

    def serve_userauth(self):
        authenticated = False
        for i in range(self.authentication_max_attempts):
            m = self.read_message(SSHMessageID.USERAUTH_REQUEST)
            username = m.get_string().decode()
            service_name = m.get_string().decode()
            self.auth_username = username
            self.auth_service_name = service_name
            method_name = m.get_string().decode()
            print("username", username)
            print("service_name", service_name)
            print("method_name", method_name)
            if method_name == "publickey":
                _expect(m.get_boolean() is False, "expected false")
                public_key_algo = m.get_string().decode()
                public_key_data = m.get_string()
                authenticated = self.auth_with_publickey(
                    public_key_algo, public_key_data
                )
                if authenticated:
                    break
            elif method_name == "password":
                _expect_eq(m.get_boolean(), False)
                password = m.get_string().decode()
                authenticated = self.auth_with_password(password)
                if authenticated:
                    break

            m = Message()
            m.add_message_id(SSHMessageID.USERAUTH_FAILURE)
            # m.add_name_list("publickey", "password")
            m.add_name_list("password")
            m.add_boolean(False)
            self.write_message(m)

        if authenticated:
            sm = Message()
            sm.add_message_id(SSHMessageID.USERAUTH_SUCCESS)
            self.write_message(sm)
        else:
            raise DisconnectError(
                SSHDisconnectReasonID.NO_MORE_AUTH_METHODS_AVAILABLE,
            )

    def auth_with_publickey(self, public_key_algo: str, public_key_data: bytes) -> bool:
        # https://datatracker.ietf.org/doc/html/rfc4252#section-7
        logger.debug("auth_with_publickey algo: %s", public_key_algo)
        # 应该要检查公钥是否在用户家目录下的 authorized_keys 文件中
        m = Message()
        m.add_message_id(SSHMessageID.USERAUTH_PK_OK)
        m.add_string(public_key_algo.encode())
        m.add_string(public_key_data)
        self.write_message(m)

        cm = self.read_message(SSHMessageID.USERAUTH_REQUEST)
        username = cm.get_string().decode()
        service_name = cm.get_string().decode()
        method_name = cm.get_string().decode()
        _expect_eq(username, self.auth_username)
        _expect_eq(service_name, self.auth_service_name)
        _expect_eq(method_name, "publickey")
        _expect_eq(cm.get_boolean(), True)
        _expect_eq(cm.get_string().decode(), public_key_algo)
        _expect_eq(cm.get_string(), public_key_data)
        signature = cm.get_string()
        # 签名结构如下
        #       string    "ssh-rsa"
        #       string    rsa_signature_blob
        sign_m = Message(signature)
        sign_m.get_string()
        signature_blob = sign_m.get_string()

        presign_m = Message()
        presign_m.add_string(self.session_id)
        presign_m.add_message_id(SSHMessageID.USERAUTH_REQUEST)
        presign_m.add_string(self.auth_username.encode())
        presign_m.add_string(self.auth_service_name.encode())
        # print("\n\npublic_key_algo", public_key_algo)
        # print("auth_username", self.auth_username)
        # print("auth_srvice_name", self.auth_service_name)
        presign_m.add_string(b"publickey")
        presign_m.add_boolean(True)
        presign_m.add_string(public_key_algo.encode())
        presign_m.add_string(public_key_data)
        message_data = presign_m.as_bytes()
        # print('message_data', message_data)
        # print('signature', signature)
        # print("public_key_data", public_key_data)
        if public_key_algo == "ssh-rsa":
            # 这个 public_key_data 的结构跟 SSHRsaHostKey 生成的 k_s 一样
            # 详情如下
            #       string    "ssh-rsa"
            #       mpint     e
            #       mpint     n
            public_key_message = Message(public_key_data)
            # 读取前面的 "ssh-rsa" 算法名
            public_key_message.get_string()
            pe = public_key_message.get_mpint()
            pn = public_key_message.get_mpint()
            # print('-------------public numbers')
            # print('     e', pe)
            # print('     n', pn)
            public_key = rsa.RSAPublicNumbers(pe, pn).public_key()
            try:
                public_key.verify(
                    signature_blob,
                    message_data,
                    PKCS1v15(),
                    hashes.SHA1(),
                )
            except cryptography.exceptions.InvalidSignature:
                logger.exception("invalid signature")
                return False
            logger.info("user %s auth public key successfully", self.auth_username)
            return True
        logger.error("unsupported publickey algorithm: %s", public_key_algo)
        return False

    def auth_with_password(self, password: str) -> bool:
        # https://datatracker.ietf.org/doc/html/rfc4252#section-8
        logger.debug("auth_with_password")
        print("password", password)
        return bool(password)

    def serve_connection(self):
        pass

    # def start_as_client(self):
    #     self.side = SSHSide.client
    #     raise NotImplementedError("start_as_client")

    def exchange_protocol_version(self):
        """双方交换协议版本，数据格式如下
        SSH-<protoversion>-<softwareversion>\r\n
        SSH-<protoversion>-<softwareversion> <comments>\r\n

        comments 是可选的，如果需要添加，则要用空格分隔。

        ref: https://datatracker.ietf.org/doc/html/rfc4253#section-4.2
        """
        self._sock.sendall(self.server_version_data + b"\r\n")
        line = self._rfile.readline()
        line = line.strip()
        self.client_version_data = line
        logger.info('Receive "%s"', line.decode())
        parts = line.split(b"-", 2)
        _expect(len(parts) == 3 and parts[0] == b"SSH", "invalid protocol version data")
        if parts[1] != b"2.0":
            raise DisconnectError(
                SSHDisconnectReasonID.PROTOCOL_VERSION_NOT_SUPPORTED,
            )

    def negotiate_algorithm(self):
        """服务端和客户端双方协商算法

        https://datatracker.ietf.org/doc/html/rfc4253#section-7.1

        算法消息结构如下

        byte         SSH_MSG_KEXINIT
        byte[16]     cookie (random bytes)
        name-list    kex_algorithms
        name-list    server_host_key_algorithms
        name-list    encryption_algorithms_client_to_server
        name-list    encryption_algorithms_server_to_client
        name-list    mac_algorithms_client_to_server
        name-list    mac_algorithms_server_to_client
        name-list    compression_algorithms_client_to_server
        name-list    compression_algorithms_server_to_client
        name-list    languages_client_to_server
        name-list    languages_server_to_client
        boolean      first_kex_packet_follows
        uint32       0 (reserved for future extension)
        """
        client_msg = self.read_message(SSHMessageID.KEXINIT)
        self.client_algorithms_message = client_msg
        client_msg.get_raw_bytes(16)
        # 协商算法过程如下
        # 遍历客户端传来的算法，找到第一个服务端也支持的
        adopted_algo = self._adopted_algo
        kex_algorithms = client_msg.get_name_list()
        logger.debug("client kex_algorithms: %s", kex_algorithms)
        for algo in kex_algorithms:
            if algo in self.kex_algorithms:
                adopted_algo.kex = algo
                break

        server_host_key_algorithms = client_msg.get_name_list()
        logger.debug(
            "client server_host_key_algorithms: %s", server_host_key_algorithms
        )
        for algo in server_host_key_algorithms:
            if algo in self.server_host_key_algorithms:
                adopted_algo.server_host_key = algo
                break

        encryption_algorithms_client_to_server = client_msg.get_name_list()
        logger.debug(
            "client encryption_algorithms_client_to_server: %s",
            encryption_algorithms_client_to_server,
        )
        for algo in encryption_algorithms_client_to_server:
            if algo in self.encryption_algorithms:
                adopted_algo.encryption_cs = algo
                break

        encryption_algorithms_server_to_client = client_msg.get_name_list()
        logger.debug(
            "client encryption_algorithms_server_to_client: %s",
            encryption_algorithms_server_to_client,
        )
        for algo in encryption_algorithms_server_to_client:
            if algo in self.encryption_algorithms:
                adopted_algo.encryption_sc = algo
                break

        mac_algorithms_client_to_server = client_msg.get_name_list()
        logger.debug(
            "client mac_algorithms_client_to_server: %s",
            mac_algorithms_client_to_server,
        )
        for algo in mac_algorithms_client_to_server:
            if algo in self.mac_algorithms:
                adopted_algo.mac_cs = algo
                break

        mac_algorithms_server_to_client = client_msg.get_name_list()
        logger.debug(
            "client mac_algorithms_server_to_client: %s",
            mac_algorithms_server_to_client,
        )
        for algo in mac_algorithms_server_to_client:
            if algo in self.mac_algorithms:
                adopted_algo.mac_sc = algo
                break

        # chacha20-poly1305@openssh.com 不需要额外的 MAC
        if adopted_algo.encryption_cs in self.aead_encryption_algorithms:
            adopted_algo.mac_cs = "<implicit>"
        if adopted_algo.encryption_sc in self.aead_encryption_algorithms:
            adopted_algo.mac_sc = "<implicit>"

        compression_algorithms_client_to_server = client_msg.get_name_list()
        for algo in compression_algorithms_client_to_server:
            if algo in self.compression_algorithms:
                adopted_algo.compression_cs = algo
                break

        compression_algorithms_server_to_client = client_msg.get_name_list()
        for algo in compression_algorithms_server_to_client:
            if algo in self.compression_algorithms:
                adopted_algo.compression_sc = algo
                break

        # 没有 language 直接忽略
        client_msg.get_name_list()
        client_msg.get_name_list()

        # 密钥算法猜测，不支持
        first_kex_packet_follows = client_msg.get_boolean()
        if first_kex_packet_follows:
            raise UnsupportedError("unsupported option first_kex_packet_follows")

        client_msg.get_uint32()

        checks = {
            "kex_algorithms": (adopted_algo.kex, kex_algorithms),
            "server_host_key_algorithms": (
                adopted_algo.server_host_key,
                server_host_key_algorithms,
            ),
            "encryption_algorithms_client_to_server": (
                adopted_algo.encryption_cs,
                encryption_algorithms_client_to_server,
            ),
            "encryption_algorithms_server_to_client": (
                adopted_algo.encryption_sc,
                encryption_algorithms_server_to_client,
            ),
            "mac_algorithms_client_to_server": (
                adopted_algo.mac_cs,
                mac_algorithms_client_to_server,
            ),
            "mac_algorithms_server_to_client": (
                adopted_algo.mac_sc,
                mac_algorithms_server_to_client,
            ),
            "compression_algorithms_client_to_server": (
                adopted_algo.compression_cs,
                compression_algorithms_client_to_server,
            ),
            "compression_algorithms_server_to_client": (
                adopted_algo.compression_sc,
                compression_algorithms_server_to_client,
            ),
        }
        for name, (algo, client_algos) in checks.items():
            if not algo:
                logger.error(
                    "no matching %s found. Remote offer: [%s]",
                    name,
                    ",".join(client_algos),
                )
                raise DisconnectError(
                    SSHDisconnectReasonID.KEY_EXCHANGE_FAILED,
                    f"no matching {name} found",
                )

        self.write_message(self.server_algorithms_message)
        logger.debug("kex: algorithm: %s", adopted_algo.kex)
        logger.debug("kex: host key algorithm: %s", adopted_algo.server_host_key)
        logger.debug(
            "kex: server->client cipher: %s MAC: %s compression: %s",
            adopted_algo.encryption_sc,
            adopted_algo.mac_sc,
            adopted_algo.compression_sc,
        )
        logger.debug(
            "kex: client->server cipher: %s MAC: %s compression: %s",
            adopted_algo.encryption_cs,
            adopted_algo.mac_cs,
            adopted_algo.compression_cs,
        )

    def exchange_key(self):
        """交换密钥

        ec 密钥交换，说明了一个大概流程
        https://datatracker.ietf.org/doc/html/rfc5656#section-4
        交换之后密钥的计算
        https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
        交换算法 curve25519-sha256
        """
        try:
            kex_cls = get_kex_obj(self._adopted_algo.kex)
        except KeyError:
            m = self.read_message()
            print(m.as_bytes())
            raise
        kex = kex_cls(self, self.session_id)
        self.kex_result = kex.do_server_exchange()
        if not self.session_id:
            self.session_id = self.kex_result.session_id

        # 发送 SSH_MSG_NEWKEYS
        m = Message()
        m.add_message_id(SSHMessageID.NEWKEYS)
        self.write_message(m)

        # client 也会发送 SSH_MSG_NEWKEYS
        self.read_message(SSHMessageID.NEWKEYS)

        adopted = self._adopted_algo
        # write: server to client
        new_packet_writer = self._get_packet_io(
            adopted.encryption_sc,
            adopted.mac_sc,
            adopted.compression_sc,
            server_tag,
        )
        self._packet_writer = new_packet_writer
        # read: client to server
        new_packet_reader = self._get_packet_io(
            adopted.encryption_cs,
            adopted.mac_cs,
            adopted.compression_cs,
            client_tag,
        )
        self._packet_reader = new_packet_reader

    @staticmethod
    def openssh_public_key_fingerprint(key: bytes) -> bytes:
        """按 openssh 方式计算公钥的 fingerprint

        :param key: ssh 格式的公钥数据，类似下面的结构，
            ssh-rsa AAAAB3Nza user
            算法 公钥的base64编码 用户名
        :return: 公钥指纹
        """
        parts = key.split()
        key_data = base64.b64decode(parts[1])
        digest = hashlib.sha256(key_data).digest()
        return base64.b64encode(digest)

    def _get_packet_io(
            self,
            encryption_algo: str,
            mac_algo: str,
            compression_algo: str,
            cipher_tag: "CipherTag",
    ) -> "PacketIOInterface":
        print("_get_packet_io", encryption_algo, mac_algo, compression_algo)
        if encryption_algo in self.aead_encryption_algorithms:
            if encryption_algo == "chacha20-poly1305@openssh.com":
                return Chacha20Poly1305PacketIO(
                    self._sock,
                    self._packet_writer.write_seq_num,
                    self._packet_reader.read_seq_num,
                    self.kex_result,
                    cipher_tag,
                )
            if encryption_algo == "aes128-gcm@openssh.com":
                return AES128GCMCipherPacketIO(
                    self._sock,
                    self._packet_writer.write_seq_num,
                    self._packet_reader.read_seq_num,
                    self.kex_result,
                    cipher_tag,
                )
            if encryption_algo == "aes256-gcm@openssh.com":
                return AES256GCMCipherPacketIO(
                    self._sock,
                    self._packet_writer.write_seq_num,
                    self._packet_reader.read_seq_num,
                    self.kex_result,
                    cipher_tag,
                )
        mac_impl = get_mac_impl(mac_algo)
        if encryption_algo == "aes128-ctr":
            return AES128CtrCipherPacketIO(
                self._sock,
                self._packet_writer.write_seq_num,
                self._packet_reader.read_seq_num,
                self.kex_result,
                mac_impl(),
                cipher_tag,
            )
        if encryption_algo == "aes192-ctr":
            return AES192CtrCipherPacketIO(
                self._sock,
                self._packet_writer.write_seq_num,
                self._packet_reader.read_seq_num,
                self.kex_result,
                mac_impl(),
                cipher_tag,
            )
        if encryption_algo == "aes256-ctr":
            return AES256CtrCipherPacketIO(
                self._sock,
                self._packet_writer.write_seq_num,
                self._packet_reader.read_seq_num,
                self.kex_result,
                mac_impl(),
                cipher_tag,
            )

        raise UnsupportedError(
            "unsupported algorithm cipher: %s, MAC: %s, compression: %s",
            encryption_algo,
            mac_algo,
            compression_algo,
        )

    def _build_server_algorithms_message(self) -> "Message":
        """构建服务端支持算法消息

        算法消息结构如下

        byte         SSH_MSG_KEXINIT
        byte[16]     cookie (random bytes)
        name-list    kex_algorithms
        name-list    server_host_key_algorithms
        name-list    encryption_algorithms_client_to_server
        name-list    encryption_algorithms_server_to_client
        name-list    mac_algorithms_client_to_server
        name-list    mac_algorithms_server_to_client
        name-list    compression_algorithms_client_to_server
        name-list    compression_algorithms_server_to_client
        name-list    languages_client_to_server
        name-list    languages_server_to_client
        boolean      first_kex_packet_follows
        uint32       0 (reserved for future extension)
        """
        message = Message()
        message.add_message_id(SSHMessageID.KEXINIT)
        message.add_raw_bytes(secrets.token_bytes(16))
        message.add_name_list(*self.kex_algorithms)
        message.add_name_list(*self.server_host_key_algorithms)
        # 加密、Mac、压缩、语言都分为 client_to_server 和 server_to_client
        message.add_name_list(*self.encryption_algorithms)
        message.add_name_list(*self.encryption_algorithms)
        message.add_name_list(*self.mac_algorithms)
        message.add_name_list(*self.mac_algorithms)
        message.add_name_list(*self.compression_algorithms)
        message.add_name_list(*self.compression_algorithms)
        message.add_name_list(*self.languages)
        message.add_name_list(*self.languages)
        message.add_boolean(False)
        message.add_uint32(0)
        return message

    def setup_server(self):
        """设置服务器。
        加载机器的 host key
        """
        mapping = {
            "ecdsa-sha2-nistp256": EcdsaSha2Nistp256HostKey,
            "ssh-ed25519": SSHEd25519HostKey,
            "ssh-rsa": SSHRsaHostKey,
            # "ssh-dss": SSHDssHostKey,
        }
        pub_paths = SSH_DIR.glob("ssh_host_*_key.pub")
        for pub_path in pub_paths:
            s = string_from_file(pub_path)
            algo = s.split()[0]
            key_cls = mapping.get(algo)
            if key_cls is None:
                continue
            name = pub_path.stem
            key_ins = key_cls(
                bytes_from_file(pub_path),
                bytes_from_file(SSH_DIR / name),
            )
            self.server_host_keys[algo] = key_ins
            if algo == "ssh-rsa":
                self.server_host_keys["rsa-sha2-256"] = SSHRsaSha256HostKey(
                    bytes_from_file(pub_path),
                    bytes_from_file(SSH_DIR / name),
                )
                self.server_host_keys["rsa-sha2-512"] = SSHRsaSha512HostKey(
                    bytes_from_file(pub_path),
                    bytes_from_file(SSH_DIR / name),
                )

        support_host_key_algorithms = []
        for algo in self.support_server_host_key_algorithms:
            if algo in self.server_host_keys:
                support_host_key_algorithms.append(algo)
        self.server_host_key_algorithms = tuple(support_host_key_algorithms)
        self.server_algorithms_message = self._build_server_algorithms_message()

    def get_server_host_key(self) -> "ServerHostKeyBase":
        """读取 server 的 host key 。
        对于服务器而言，这个 key 文件一般是下面几个

        /etc/ssh/ssh_host_ecdsa_key.pub
        /etc/ssh/ssh_host_rsa_key.pub
        /etc/ssh/ssh_host_ed25519_key.pub

        分别代表 ecdsa rsa ed25519 算法，也可以通过 ssh-keygen -A 生成这三个文件
        如果要在当前文件夹生成，可以执行下面的命令
        mkdir -p etc/ssh
        ssh-keygen -A -f .
        生成的 key 文件在 ./etc/ssh/
        """
        return self.server_host_keys[self._adopted_algo.server_host_key]

    def disconnect(self, reason_id: SSHDisconnectReasonID, description: str):
        m = Message()
        m.add_message_id(SSHMessageID.DISCONNECT)
        m.add_uint32(reason_id.value)
        m.add_string(description.encode())
        m.add_string(b"en")
        self.write_message(m)

    def read_message(
            self, expected_message_id: t.Optional[SSHMessageID] = None
    ) -> "Message":
        payload = self._packet_reader.read_packet()
        m = Message(payload)
        if expected_message_id is not None:
            mid = m.get_message_id()
            _expect(
                expected_message_id == mid,
                f"expected message {expected_message_id}, but got {mid}",
            )
        return m

    def write_message(self, m: "Message") -> None:
        self._packet_writer.write_packet(m.as_bytes())


class SSHTransportHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = SSHServerTransport(self.request)
        server.start()


def prepare_server_host_key():
    """生成 server host key"""
    if not SSH_DIR.exists():
        SSH_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    matchs = list(SSH_DIR.glob("ssh_host_*_key"))
    if matchs:
        logger.debug(
            "Exist server host key in %s: [%s]",
            str(SSH_DIR),
            ",".join(str(x) for x in matchs),
        )
        return
    # 生成 server host key
    # -f 使用 etc/ssh 所在文件夹，因为生成的文件会自动加上 etc/ssh 的路径
    args = ["ssh-keygen", "-A", "-f", str(SSH_DIR.parents[1])]
    subprocess.check_call(args)
    logger.debug("Generate server host key in %s", str(SSH_DIR))


def generate_moduli(bits: int, min_count: int) -> t.List[str]:
    """生成对应比特数的 moduli 数据，数据数量最小为 min_count 。"""
    cmd = f"ssh-keygen -M generate -O bits={bits} moduli-{bits}.candidates"
    generate_args = shlex.split(cmd)
    cmd = f"ssh-keygen -M screen -f moduli-{bits}.candidates moduli-{bits}"
    screen_args = shlex.split(cmd)
    mapping = {}
    while True:
        subprocess.check_call(generate_args)
        subprocess.check_call(screen_args)

        lines = lines_from_file(f"moduli-{bits}")
        for line in lines:
            line = line.strip()
            if line.startswith("#"):
                # 注释
                continue
            # 因为数字是随机生成，多次生成可能出现重复数据，需要对数据进行去重
            time_s, data = line.split(" ", 1)
            mapping[data] = line
        if len(mapping) >= min_count:
            break
    return list(mapping.values())


def prepare_moduli():
    """生成用于 Diffie-Hellman 密钥交换的随机素数"""
    moduli_path = SSH_DIR / "moduli"
    if moduli_path.exists():
        logger.debug("Exist moduli file in %s", str(SSH_DIR))
        return
    temp_dir = tempfile.TemporaryDirectory(dir=FILE_DIR)
    old_cwd = os.getcwd()
    # 这里使用的数字都是根据系统的 /etc/ssh/moduli 的文件来的
    # want_list = [2048, 3072, 4096, 6144, 7680, 8192]
    # 生成几个测试即可，全部生成太久了
    want_list = [2048]
    try:
        os.chdir(temp_dir.name)
        total_lines = ["# Time Type Tests Tries Size Generator Modulus"]
        for n in want_list:
            lines = generate_moduli(n, 10)
            total_lines.extend(lines)
        with open(SSH_DIR / "moduli", "w", encoding="utf-8") as f:
            f.write("\n".join(total_lines))
    finally:
        os.chdir(old_cwd)
        temp_dir.cleanup()


def prepare_ssh_server():
    """启动 ssh server 前的准备"""
    prepare_server_host_key()
    prepare_moduli()


def main():
    prepare_ssh_server()
    server_address = ("127.0.0.1", 10022)
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(server_address, SSHTransportHandler)
    logger.info("SSH server listen at %s:%s", server_address[0], server_address[1])
    server.serve_forever()


if __name__ == "__main__":
    main()
