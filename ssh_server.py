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
import copy
import dataclasses
import enum
import fcntl
import hashlib
import os
import pathlib
import pwd
import queue
import secrets
import select
import shlex
import signal
import socket
import socketserver
import struct
import subprocess
import tempfile
import termios
import threading
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
import ssh_mac
from error import (
    BadRequestError,
    DisconnectError,
    PacketTooLargeError,
    UnexpectedError,
    UnsupportedError,
)
from message import (
    Message,
    SSHDisconnectReasonID,
    SSHExtendedDataType,
    SSHMessageID,
    SSHOpenReasonCode,
)

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


def _setwinsize(fd, rows, cols):
    """设置 pty 窗口大小
    code from https://github.com/pexpect/ptyprocess/blob/ce42a786ff6f4baff71382db9076c7398328abaf/ptyprocess/ptyprocess.py#L118
    """
    # Some very old platforms have a bug that causes the value for
    # termios.TIOCSWINSZ to be truncated. There was a hack here to work
    # around this, but it caused problems with newer platforms so has been
    # removed. For details see https://github.com/pexpect/pexpect/issues/39
    TIOCSWINSZ = getattr(termios, "TIOCSWINSZ", -2146929561)
    # Note, assume ws_xpixel and ws_ypixel are zero.
    s = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, TIOCSWINSZ, s)


def string_from_file(filepath: t.Union[str, pathlib.Path]) -> str:
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def bytes_from_file(filepath: t.Union[str, pathlib.Path]) -> bytes:
    with open(filepath, "rb") as f:
        return f.read()


def lines_from_file(filepath: t.Union[str, pathlib.Path]) -> t.List[str]:
    with open(filepath, "r", encoding="utf-8") as f:
        return list(f)


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


#################################
# 密钥交换支持
#################################
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

    # noinspection PyUnusedLocal
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
        m.add_string(self._q_c)
        m.add_string(self._q_s)
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


class EcdhSha2Nistp384Kex(EcdhSha2Nistp256Kex):
    hash_call = hashlib.sha384
    curve_cls = ec.SECP384R1


class EcdhSha2Nistp521Kex(EcdhSha2Nistp256Kex):
    hash_call = hashlib.sha512
    curve_cls = ec.SECP521R1


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
# packet 读写支持，包含加解密、 mac 等处理
#################################


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

    # 读写 packet 编号，从 0 开始计数
    read_seq_num: int
    write_seq_num: int

    @abc.abstractmethod
    def read_packet(self) -> bytes:
        raise NotImplementedError("read_packet")

    @abc.abstractmethod
    def write_packet(self, payload: bytes):
        raise NotImplementedError("write_packet")


class RawPacketIO(PacketIOInterface):
    read_timeout = 600

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
        # noinspection PyUnusedLocal
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
        padding_length = decrypted[0]
        return decrypted[1:-padding_length]

    def write_packet(self, payload: bytes):
        self.write_seq_num += 1
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
        mac_impl_cls: t.Type["ssh_mac.MacInterface"],
        cipher_tag: "CipherTag",
    ):
        super().__init__(sock, write_seq_num, read_seq_num)

        self._kex_result = kex_result
        self.mac_impl_cls = mac_impl_cls

        self._iv = b""
        self._key = b""
        self._mac_key = b""

        self._iv = self._kex_result.compute_key(self.block_size, cipher_tag.iv_tag)
        self._key = self._kex_result.compute_key(self.key_size, cipher_tag.key_tag)
        self._mac_key = self._kex_result.compute_key(
            self.mac_impl_cls.key_size, cipher_tag.mac_tag
        )
        self.mac_impl = mac_impl_cls(self._mac_key)

        cipher = Cipher(self.cipher_algo(self._key), modes.CTR(self._iv))
        decryptor = cipher.decryptor()
        self.decryptor = decryptor

        cipher = Cipher(self.cipher_algo(self._key), modes.CTR(self._iv))
        encryptor = cipher.encryptor()
        self.encryptor = encryptor

    def read_packet(self) -> bytes:
        self.read_seq_num += 1
        seq_bytes = self.read_seq_num.to_bytes(self.mac_impl.seq_bytes, "big")
        length_bytes = self._read_full(4)
        if self.mac_impl.is_etm:
            # 长度是明文
            packet_length = int.from_bytes(length_bytes, "big")
            if packet_length > self.max_packet:
                raise PacketTooLargeError(f"packet too large: {packet_length}")
            ciphertext = self._read_full(packet_length)
            mac = self._read_full(self.mac_impl.length)
            if not self.mac_impl.verify(seq_bytes + length_bytes + ciphertext, mac):
                raise DisconnectError(
                    SSHDisconnectReasonID.MAC_ERROR,
                )
            decryptor = self.decryptor
            plaintext = decryptor.update(ciphertext)
        else:
            # 长度是密文
            decryptor = self.decryptor
            decrypted_length_bytes = decryptor.update(length_bytes)
            packet_length = int.from_bytes(decrypted_length_bytes, "big")
            if packet_length > self.max_packet:
                raise PacketTooLargeError(f"packet too large: {packet_length}")
            ciphertext = self._read_full(packet_length)
            mac = self._read_full(self.mac_impl.length)
            plaintext = decryptor.update(ciphertext)
            if not self.mac_impl.verify(
                seq_bytes + decrypted_length_bytes + plaintext, mac
            ):
                raise DisconnectError(
                    SSHDisconnectReasonID.MAC_ERROR,
                )
        padding_length = plaintext[0]
        payload = plaintext[1:-padding_length]
        return payload

    def write_packet(self, payload: bytes):
        self.write_seq_num += 1
        seq_bytes = self.write_seq_num.to_bytes(self.mac_impl.seq_bytes, "big")
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
            # cipher = Cipher(self.cipher_algo(self._key), modes.CTR(self._iv))
            encryptor = self.encryptor
            ciphertext = encryptor.update(plaintext)
            # 计算加密数据的 mac
            mac = self.mac_impl.calculate(
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
            # cipher = Cipher(self.cipher_algo(self._key), modes.CTR(self._iv))
            # encryptor = cipher.encryptor()
            encryptor = self.encryptor
            ciphertext = encryptor.update(plaintext)
            # 计算原始数据的 mac
            print("     mac message length", len(seq_bytes + plaintext))
            mac = self.mac_impl.calculate(
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
        if packet_length > self.max_packet:
            raise PacketTooLargeError(f"packet too large: {packet_length}")

        ciphertext = self._read_full(packet_length + self.tag_size)
        aesgcm = AESGCM(self._key)
        plaintext = aesgcm.decrypt(self._iv, ciphertext, length_bytes)
        padding_length = plaintext[0]
        payload = plaintext[1:-padding_length]
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
# channel 支持
#################################
class Channel:
    """The Secure Shell (SSH) Connection Protocol: https://datatracker.ietf.org/doc/html/rfc4254"""

    # 下面两个值取自 openssh client
    channel_window_size = 1048576  # 1024kb
    channel_maximum_packet_size = 16384  # 16k
    channel_window_adjust_size = channel_window_size  # 1024kb
    channel_window_threshold = channel_window_size // 2
    channel_window_maximum_size = 2**32 - 1

    def __init__(
        self,
        channel_type: str,
        remote_id: int,
        remote_window_size: int,
        remote_maximum_packet_size: int,
    ):
        self.type = channel_type
        # 取个不一样的值，测试代码是否处理正确
        self.local_id = remote_id + 1
        self.local_window_size = self.channel_window_size
        self.local_window_remainder = self.local_window_size
        self.local_maximum_packet_size = self.channel_maximum_packet_size
        self.remote_id = remote_id
        self.remote_window_size = remote_window_size
        self.remote_window_remainder = remote_window_size
        self.remote_maximum_packet_size = remote_maximum_packet_size
        self.rtype = ""

        self.local_closed = False
        self.remote_closed = False

        self.remote_envs: t.Dict[str, str] = {}

        self.lock = threading.RLock()
        self.write_queue: queue.Queue[t.Optional["Message"]] = queue.Queue()

        self.pty_master = -1
        self.pty_slave = -1
        self.subprocess: t.Optional[subprocess.Popen] = None

        self.terminal_width = 0
        self.terminal_height = 0

        self.signal_mapping = {
            "ABRT": signal.SIGABRT,
            "ALRM": signal.SIGALRM,
            "FPE": signal.SIGFPE,
            "HUP": signal.SIGHUP,
            "ILL": signal.SIGILL,
            "INT": signal.SIGINT,
            "KILL": signal.SIGKILL,
            "PIPE": signal.SIGPIPE,
            "QUIT": signal.SIGQUIT,
            "SEGV": signal.SIGSEGV,
            "TERM": signal.SIGTERM,
            "USR1": signal.SIGUSR1,
            "USR2": signal.SIGUSR2,
        }
        pass

    def handle(self, message: Message):
        mid = message.get_message_id()
        # local channel id
        message.get_uint32()
        if mid == SSHMessageID.CHANNEL_DATA:
            self.handle_data(message)
            return
        if mid == SSHMessageID.CHANNEL_EXTENDED_DATA:
            self.handle_extended_data(message)
            return
        if mid == SSHMessageID.CHANNEL_REQUEST:
            self.handle_request(message)
            return
        if mid == SSHMessageID.CHANNEL_WINDOW_ADJUST:
            self.handle_window_adjust(message)
            return
        if mid == SSHMessageID.CHANNEL_CLOSE:
            self.handle_close(message)
            return

        logger.error(
            "channel[%s:%s] receive unsupported message", self.local_id, self.remote_id
        )

    def handle_data(self, message: "Message"):
        data_length = message.get_uint32()
        if (
            data_length > self.local_window_remainder
            or data_length > self.remote_maximum_packet_size
        ):
            # 直接忽略超过限制的数据
            logger.error(
                "channel[%s:%s] receive too many data, ignore it",
                self.local_id,
                self.remote_id,
            )
            return
        data = message.get_raw_bytes(data_length)
        self.local_window_remainder -= data_length
        if self.subprocess:
            os.write(self.pty_master, data)

        self.adjust_window_size()

    def handle_request(self, message: "Message"):
        request_type = message.get_string().decode()
        want_reply = message.get_boolean()
        reply_message_id = SSHMessageID.CHANNEL_SUCCESS
        if request_type == "pty-req":
            term = message.get_string().decode()
            self.remote_envs["TERM"] = term
            terminal_width_columns = message.get_uint32()
            terminal_height_rows = message.get_uint32()
            terminal_width_pixels = message.get_uint32()
            terminal_height_pixels = message.get_uint32()
            self.terminal_width = terminal_width_columns or terminal_width_pixels
            self.terminal_height = terminal_height_rows or terminal_height_pixels
            # https://datatracker.ietf.org/doc/html/rfc4254#section-8
            encoded_terminal_modes = message.get_string()
            logger.debug(
                "channel[%s] pty-req receive, term: %s, terminal_width_columns: %s, terminal_height_row: %s, "
                "terminal_width_pixels: %s, terminal_height_pixels: %s, encoded_terminal_modes: %s",
                self.local_id,
                term,
                terminal_width_columns,
                terminal_height_rows,
                terminal_width_pixels,
                terminal_height_pixels,
                encoded_terminal_modes,
            )
        elif request_type == "env":
            name = message.get_string().decode()
            value = message.get_string().decode()
            self.remote_envs[name] = value
        elif request_type == "shell":
            if self.rtype:
                raise DisconnectError(
                    SSHDisconnectReasonID.PROTOCOL_ERROR,
                    "invalid request type",
                )
            self.rtype = "shell"
            if self.subprocess is not None:
                reply_message_id = SSHMessageID.CHANNEL_FAILURE
            else:
                self.pty_master, self.pty_slave = os.openpty()
                _setwinsize(self.pty_master, self.terminal_height, self.terminal_width)
                # 暂时用当前用户
                username = os.environ["USER"]
                pw_record = pwd.getpwnam(username)
                env = copy.deepcopy(self.remote_envs)
                env["HOME"] = pw_record.pw_dir
                env["LOGNAME"] = pw_record.pw_name
                env["PWD"] = pw_record.pw_dir
                env["USER"] = pw_record.pw_name
                env["SHELL"] = pw_record.pw_shell
                popen = subprocess.Popen(
                    pw_record.pw_shell,
                    stdin=self.pty_slave,
                    stdout=self.pty_slave,
                    stderr=self.pty_slave,
                    cwd=pw_record.pw_dir,
                    env=env,
                    preexec_fn=demote(pw_record.pw_uid, pw_record.pw_gid),
                    start_new_session=True,
                )
                self.subprocess = popen
                # 开线程负责读取 shell 子进程的输出
                th = threading.Thread(target=self.read_shell_work, daemon=True)
                th.start()
                os.close(self.pty_slave)
        elif request_type == "exec":
            if self.rtype:
                raise DisconnectError(
                    SSHDisconnectReasonID.PROTOCOL_ERROR,
                    "invalid request type",
                )
            self.rtype = "exec"
            # 暂时用当前用户
            username = os.environ["USER"]
            pw_record = pwd.getpwnam(username)
            env = copy.deepcopy(self.remote_envs)
            env["HOME"] = pw_record.pw_dir
            env["LOGNAME"] = pw_record.pw_name
            env["PWD"] = pw_record.pw_dir
            env["USER"] = pw_record.pw_name
            env["SHELL"] = pw_record.pw_shell
            command = message.get_string().decode()
            logger.info(
                "channel[%s:%s] exec command: '%s'",
                self.local_id,
                self.remote_id,
                command,
            )
            completed_process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                cwd=pw_record.pw_dir,
                env=env,
                preexec_fn=demote(pw_record.pw_uid, pw_record.pw_gid),
                start_new_session=True,
            )
            self.write_data(completed_process.stdout)
            self.write_extended_data(
                completed_process.stderr, SSHExtendedDataType.STDERR
            )
        elif request_type == "signal":
            signal_name = message.get_string().decode()
            signal_num = self.signal_mapping[signal_name]
            logger.debug(
                "channel[%s] receive signal %s:%s",
                self.local_id,
                signal_name,
                signal_num,
            )
            if self.subprocess:
                self.subprocess.send_signal(signal_num)
        elif request_type == "window-change":
            if self.pty_master > 0:
                terminal_width_columns = message.get_uint32()
                terminal_height_rows = message.get_uint32()
                terminal_width_pixels = message.get_uint32()
                terminal_height_pixels = message.get_uint32()
                self.terminal_width = terminal_width_columns or terminal_width_pixels
                self.terminal_height = terminal_height_rows or terminal_height_pixels
                logger.debug(
                    "channel[%s:%s] change window to w: %s, h: %s",
                    self.local_id,
                    self.remote_id,
                    self.terminal_width,
                    self.terminal_height,
                )
                _setwinsize(self.pty_master, self.terminal_height, self.terminal_width)
        else:
            logger.error(
                "channel[%s:%s] receive unsupported request_type: %s",
                self.local_id,
                self.remote_id,
                request_type,
            )
            reply_message_id = SSHMessageID.CHANNEL_FAILURE

        if want_reply or reply_message_id == SSHMessageID.CHANNEL_FAILURE:
            m = Message()
            m.add_message_id(reply_message_id)
            m.add_uint32(self.remote_id)
            self.write_queue.put(m)

    def handle_window_adjust(self, message: "Message"):
        size = message.get_uint32()
        if self.remote_window_size + size > self.channel_window_maximum_size:
            return
        self.remote_window_size += size
        with self.lock:
            self.remote_window_remainder += size

    def handle_extended_data(self, message: "Message"):
        data_type_code = message.get_uint32()
        data_length = message.get_uint32()
        if (
            data_length > self.local_window_remainder
            or data_length > self.local_maximum_packet_size
        ):
            logger.error(
                "channel[%s:%s] receive to many data, just ignore it",
                self.local_id,
                self.remote_id,
            )
            # 直接忽略超过限制的数据
            return
        data = message.get_raw_bytes(data_length)
        if data_type_code == SSHExtendedDataType.STDERR:
            logger.info(
                "channel[%s:%s] receive stderr data: %s",
                self.local_id,
                self.remote_id,
                data,
            )
        self.local_window_remainder -= data_length
        self.adjust_window_size()

    def read_shell_work(self):
        read_size = self.remote_maximum_packet_size // 2
        while True:
            try:
                buf = os.read(self.pty_master, read_size)
            except OSError:
                break
            if buf == b"":
                break

            with self.lock:
                if len(buf) > self.remote_window_remainder:
                    logger.info(
                        "channel[%s:%s] remote windows not enough, abandon data",
                        self.local_id,
                        self.remote_id,
                    )
                    continue
                self.remote_window_remainder -= len(buf)
            m = Message()
            m.add_message_id(SSHMessageID.CHANNEL_DATA)
            m.add_uint32(self.remote_id)
            m.add_string(buf)
            self.write_queue.put(m)

    # noinspection PyUnusedLocal
    def handle_close(self, message: "Message"):
        self.remote_closed = True
        if not self.local_closed:
            self.close()

    def adjust_window_size(self):
        if self.local_window_remainder >= self.channel_window_threshold:
            return
        # 剩余窗口太小，增加窗口大小
        adjust_size = min(
            self.channel_window_adjust_size,
            self.channel_window_maximum_size - self.local_window_size,
        )
        if adjust_size <= 0:
            # 已达到最大窗口大小，没有可以增加的了
            return
        m = Message()
        m.add_message_id(SSHMessageID.CHANNEL_WINDOW_ADJUST)
        m.add_uint32(self.remote_id)
        m.add_uint32(adjust_size)
        self.write_queue.put(m)
        self.local_window_remainder += adjust_size

    def close(self):
        m = Message()
        m.add_message_id(SSHMessageID.CHANNEL_CLOSE)
        m.add_uint32(self.remote_id)
        self.write_queue.put(m)

    def work(self):
        if self.subprocess and self.subprocess.poll() is not None:
            returncode = self.subprocess.wait()
            self.subprocess = None
            self.pty_master = -1
            self.pty_slave = -1
            self.write_exit_status_message(returncode)
            self.close()

    def flush_write(self, transport: "SSHServerTransport"):
        while True:
            try:
                m = self.write_queue.get_nowait()
            except queue.Empty:
                break

            if m is None:
                break

            transport.write_message(m)

    def write_exit_status_message(self, exit_code: int):
        m = Message()
        m.add_message_id(SSHMessageID.CHANNEL_REQUEST)
        m.add_uint32(self.remote_id)
        m.add_string(b"exit-status")
        m.add_boolean(False)
        m.add_uint32(exit_code)
        self.write_queue.put(m)

    def write_data(self, data: bytes):
        chunk_length = self.remote_maximum_packet_size // 2
        for i in range(0, len(data), chunk_length):
            chunk = data[i : i + chunk_length]
            with self.lock:
                if len(chunk) > self.remote_window_remainder:
                    logger.info(
                        "channel[%s:%s] remote windows not enough, abandon data",
                        self.local_id,
                        self.remote_id,
                    )
                    return
                self.remote_window_remainder -= len(chunk)
            m = Message()
            m.add_message_id(SSHMessageID.CHANNEL_DATA)
            m.add_uint32(self.remote_id)
            m.add_string(chunk)
            self.write_queue.put(m)

    def write_extended_data(self, data: bytes, data_type_code: "SSHExtendedDataType"):
        chunk_length = self.remote_maximum_packet_size // 2
        for i in range(0, len(data), chunk_length):
            chunk = data[i : i + chunk_length]
            with self.lock:
                if len(chunk) > self.remote_window_remainder:
                    logger.info(
                        "channel[%s:%s] remote windows not enough, abandon data",
                        self.local_id,
                        self.remote_id,
                    )
                    return
                self.remote_window_remainder -= len(chunk)
            m = Message()
            m.add_message_id(SSHMessageID.CHANNEL_EXTENDED_DATA)
            m.add_uint32(self.remote_id)
            m.add_uint32(data_type_code)
            m.add_string(chunk)
            self.write_queue.put(m)

    def stop(self):
        logger.info("channel[%s:%s] stop", self.local_id, self.remote_id)
        if self.subprocess:
            self.subprocess.terminate()
            try:
                returncode = self.subprocess.wait(8)
            except subprocess.TimeoutExpired:
                # 等待一段时间还没结束，直接 KILL
                self.subprocess.kill()
                returncode = self.subprocess.wait()
            logger.info(
                "channel[%s:%s] subprocess terminate, returncode: %s",
                self.local_id,
                self.remote_id,
                returncode,
            )
        self.local_closed = True
        self.remote_closed = True


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
        "curve25519-sha256",
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
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
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
        # 直接复制 openssh umac 的代码，用 C 扩展的方式提供 API 给 Python 调用
        # etm 表示先加密再对加密数据计算 MAC
        "umac-64-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha1-etm@openssh.com",
        "umac-64@openssh.com",
        "umac-128@openssh.com",
        "hmac-sha2-256",
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

        self.server_host_key_algorithms: t.Tuple[str] = ("",)
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
        self.auth_method_name = ""

        self.channel_configs: t.Dict[int, Channel] = {}
        self.channel_opened = False

        # 这两个值取自 openssh client
        self.channel_window_size = 1048576  # 1024kb
        self.channel_window_adjust_size = 1048576  # 1024kb
        self.channel_maximum_packet_size = 16384  # 16k
        # 窗口阈值，当剩余窗口小于这个值时，增加窗口大小
        self.channel_window_threshold_size = 256
        self.channel_window_maximum_size = 2**32 - 1

        # 是否使用 pty
        self.use_pty = False
        # 客户端发过来的环境变量
        self.remote_envs: t.Dict[str, str] = {}
        self.popen: t.Optional[subprocess.Popen] = None
        # shell 子进程关联的 channel id
        self.popen_channel_id = -1

        self.pty_master = -1
        self.pty_slave = -1

        self.signal_mapping = {
            "ABRT": signal.SIGABRT,
            "ALRM": signal.SIGALRM,
            "FPE": signal.SIGFPE,
            "HUP": signal.SIGHUP,
            "ILL": signal.SIGILL,
            "INT": signal.SIGINT,
            "KILL": signal.SIGKILL,
            "PIPE": signal.SIGPIPE,
            "QUIT": signal.SIGQUIT,
            "SEGV": signal.SIGSEGV,
            "TERM": signal.SIGTERM,
            "USR1": signal.SIGUSR1,
            "USR2": signal.SIGUSR2,
        }

    def start(self):
        self.side = SSHSide.server
        try:
            self._work()
        except DisconnectError as e:
            # logger.exception("disconnect")
            self.disconnect(e.reason_id, e.description)
        finally:
            for channel in self.channel_configs.values():
                channel.stop()
            self.channel_configs = {}

    def _work(self):
        self.setup_server()
        self.exchange_protocol_version()
        self.negotiate_algorithm()
        self.exchange_key()

        m = self.read_message(SSHMessageID.SERVICE_REQUEST)
        service = m.get_string()
        if service not in (b"ssh-userauth",):
            raise DisconnectError(
                SSHDisconnectReasonID.SERVICE_NOT_AVAILABLE,
                "unsupported service " + service.decode(),
            )

        m = Message()
        m.add_message_id(SSHMessageID.SERVICE_ACCEPT)
        m.add_string(service)
        self.write_message(m)

        self.serve_userauth()

        self.serve_connection()

    def serve_userauth(self) -> None:
        """用户认证，正常返回表示认证通过，否则抛出异常
        rfc: https://datatracker.ietf.org/doc/html/rfc4252

        """
        authenticated = False
        for i in range(self.authentication_max_attempts):
            m = self.read_message(SSHMessageID.USERAUTH_REQUEST)
            username = m.get_string().decode()
            service_name = m.get_string().decode()
            self.auth_username = username
            self.auth_service_name = service_name
            # 只支持 ssh-connection
            _expect_eq(service_name, "ssh-connection")
            method_name = m.get_string().decode()
            self.auth_method_name = method_name
            logger.debug(
                "start userauth, username: %s, service_name: %s, method_name: %s",
                username,
                service_name,
                method_name,
            )
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
            m.add_name_list("publickey", "password")
            # m.add_name_list("password")
            m.add_boolean(False)
            self.write_message(m)

        if authenticated:
            sm = Message()
            sm.add_message_id(SSHMessageID.USERAUTH_SUCCESS)
            self.write_message(sm)
            logger.info(
                "user auth successfully, username: %s, service_name: %s, method_name: %s",
                self.auth_username,
                self.auth_service_name,
                self.auth_method_name,
            )
        else:
            logger.info(
                "user auth too many fail, username: %s, service_name: %s, method_name: %s",
                self.auth_username,
                self.auth_service_name,
                self.auth_method_name,
            )
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
        presign_m.add_string(b"publickey")
        presign_m.add_boolean(True)
        presign_m.add_string(public_key_algo.encode())
        presign_m.add_string(public_key_data)
        message_data = presign_m.as_bytes()
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
        logger.debug("auth_with_password, username: %s", self.auth_username)
        return bool(password)

    def serve_connection(self) -> None:
        """作为连接使用，在上面传输特定的应用数据
        rfc: https://datatracker.ietf.org/doc/html/rfc4252

        """
        print("\n\nserve_connection, thread_count", threading.active_count())
        channel_message_ids = {
            SSHMessageID.CHANNEL_REQUEST,
            SSHMessageID.CHANNEL_DATA,
            SSHMessageID.CHANNEL_EXTENDED_DATA,
            SSHMessageID.CHANNEL_WINDOW_ADJUST,
            SSHMessageID.CHANNEL_CLOSE,
        }
        while True:
            # 用户输入 ctrl+d 表示退出，客户端会发送消息给服务端，等待服务端回应
            # 服务端接收消息，将消息转发给 shell 子进程，
            # shell 子进程收到消息后自己结束，服务端检测到子进程结束，发送关闭消息给客户端
            # 上述这个流程在实际实现中存在一个问题，服务端转发消息之后，检测子进程是否结束
            # 但是子进程结束需要时间，这个时候可能检测到还没结束，于是又执行到 read_message ，等待客户端发送消息
            # 可是这个时候客户端也在等待服务端发送消息，就这样两个都卡在这里
            # 所以在实现上需要注意
            rlist, wlist, xlist = select.select([self._sock.fileno()], [], [], 0.1)
            if self._sock.fileno() in rlist:
                message = self.read_message()
                mid = message.get_message_id()
                if mid == SSHMessageID.GLOBAL_REQUEST:
                    self.handle_global_reqeust(message)
                    continue
                if mid == SSHMessageID.CHANNEL_OPEN:
                    self.handle_channel_open(message)
                    continue
                if mid == SSHMessageID.DISCONNECT:
                    self.handle_disconnect(message)
                    continue
                if mid in channel_message_ids:
                    channel_id = message.get_uint32()
                    channel = self.channel_configs.get(channel_id)
                    if channel is None:
                        raise UnexpectedError(
                            f"channel {channel_id} not found",
                        )
                    message.reset()
                    channel.handle(message)
                    continue

                logger.error("receive unsupported message: %s", mid)
                raise DisconnectError(
                    SSHDisconnectReasonID.SERVICE_NOT_AVAILABLE,
                )

            for channel_id in list(self.channel_configs.keys()):
                channel = self.channel_configs[channel_id]
                channel.work()
                channel.flush_write(self)
                if channel.local_closed and channel.remote_closed:
                    self.channel_configs.pop(channel_id)

    def handle_disconnect(self, message: Message) -> None:
        reason_id = message.get_uint32()
        description = message.get_string().decode()
        lang_tag = message.get_string().decode()
        logger.info(
            "receive client disconnect message, reason_id: %s, description: %s, lang_tag: %s",
            reason_id,
            description,
            lang_tag,
        )
        raise DisconnectError(
            SSHDisconnectReasonID.BY_APPLICATION,
            "disconnect",
        )

    def handle_global_reqeust(self, message: Message) -> None:
        request_name = message.get_string()
        logger.info("SSH_MSG_GLOBAL_REQUEST received, request_name: %s", request_name)
        # 没有实现任何 global request 消息
        sm = Message()
        sm.add_message_id(SSHMessageID.REQUEST_FAILURE)
        self.write_message(sm)
        pass

    def handle_channel_open(self, message: Message):
        """新建 channel"""
        cm = message
        # channel type https://datatracker.ietf.org/doc/html/rfc4250#section-4.9.1
        channel_type = cm.get_string().decode()
        channel_id = cm.get_uint32()
        # window_size 代表总共可以发送给客户端的数据大小，
        # 所以每次发送数据给客户端，都需要扣减
        # 客户端可以发送另外的消息增加这个值
        window_size = cm.get_uint32()
        maximum_packet_size = cm.get_uint32()
        logger.info(
            "SSH_MSG_CHANNEL_OPEN received, channel_type: %s, channel_id: %s, window_size: %s, "
            "maximum_packet_size: %s",
            channel_type,
            channel_id,
            window_size,
            maximum_packet_size,
        )
        if channel_id in self.channel_configs:
            raise DisconnectError(
                SSHDisconnectReasonID.SERVICE_NOT_AVAILABLE,
            )

        if channel_type != "session":
            sm = Message()
            sm.add_message_id(SSHMessageID.CHANNEL_OPEN_FAILURE)
            sm.add_uint32(channel_id)
            sm.add_uint32(SSHOpenReasonCode.UNKNOWN_CHANNEL_TYPE)
            sm.add_string(b"unknown channel type")
            sm.add_string(b"en")
            self.write_message(sm)
        else:
            channel = Channel(
                channel_type,
                channel_id,
                window_size,
                maximum_packet_size,
            )
            self.channel_configs[channel_id] = channel
            # 回消息确认 channel 创建成功
            sm = Message()
            sm.add_message_id(SSHMessageID.CHANNEL_OPEN_CONFIRMATION)
            sm.add_uint32(channel_id)
            sm.add_uint32(channel_id)
            sm.add_uint32(channel.local_window_size)
            sm.add_uint32(channel.local_maximum_packet_size)
            self.write_message(sm)
        pass

    # def channel_eof(self, channel: SSHChannel):
    #     """本端不再发送数据，不需要对方回复"""
    #     m = Message()
    #     m.add_message_id(SSHMessageID.CHANNEL_EOF)
    #     m.add_uint32(channel.id)
    #     self.write_message(m)

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
        mac_impl_cls = ssh_mac.get_mac_impl(mac_algo)
        if encryption_algo == "aes128-ctr":
            return AES128CtrCipherPacketIO(
                self._sock,
                self._packet_writer.write_seq_num,
                self._packet_reader.read_seq_num,
                self.kex_result,
                mac_impl_cls,
                cipher_tag,
            )
        if encryption_algo == "aes192-ctr":
            return AES192CtrCipherPacketIO(
                self._sock,
                self._packet_writer.write_seq_num,
                self._packet_reader.read_seq_num,
                self.kex_result,
                mac_impl_cls,
                cipher_tag,
            )
        if encryption_algo == "aes256-ctr":
            return AES256CtrCipherPacketIO(
                self._sock,
                self._packet_writer.write_seq_num,
                self._packet_reader.read_seq_num,
                self.kex_result,
                mac_impl_cls,
                cipher_tag,
            )

        logger.error(
            "unsupported algorithm cipher: %s, MAC: %s, compression: %s",
            encryption_algo,
            mac_algo,
            compression_algo,
        )
        raise DisconnectError(
            SSHDisconnectReasonID.KEY_EXCHANGE_FAILED,
            "unsupported algorithm",
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


def demote(user_uid, user_gid):
    def result():
        os.setgid(user_gid)
        os.setuid(user_uid)

    return result


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
