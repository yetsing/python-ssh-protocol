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
import dataclasses
import enum
import hashlib
import io
import pathlib
import secrets
import socket
import socketserver
import struct
import typing as t

from cryptography.hazmat.primitives import hashes, poly1305, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

import logutil

# noinspection DuplicatedCode
SSH_MSG_DISCONNECT = 1
SSH_MSG_IGNORE = 2
SSH_MSG_UNIMPLEMENTED = 3
SSH_MSG_DEBUG = 4
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEX_ECDH_INIT = 30
SSH_MSG_KEX_ECDH_REPLY = 31
SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_FAILURE = 51
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_USERAUTH_BANNER = 53
SSH_MSG_GLOBAL_REQUEST = 80
SSH_MSG_REQUEST_SUCCESS = 81
SSH_MSG_REQUEST_FAILURE = 82
SSH_MSG_CHANNEL_OPEN = 90
SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
SSH_MSG_CHANNEL_OPEN_FAILURE = 92
SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
SSH_MSG_CHANNEL_DATA = 94
SSH_MSG_CHANNEL_EXTENDED_DATA = 95
SSH_MSG_CHANNEL_EOF = 96
SSH_MSG_CHANNEL_CLOSE = 97
SSH_MSG_CHANNEL_REQUEST = 98
SSH_MSG_CHANNEL_SUCCESS = 99
SSH_MSG_CHANNEL_FAILURE = 100

SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1
SSH_DISCONNECT_PROTOCOL_ERROR = 2
SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3
SSH_DISCONNECT_RESERVED = 4
SSH_DISCONNECT_MAC_ERROR = 5
SSH_DISCONNECT_COMPRESSION_ERROR = 6
SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7
SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8
SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9
SSH_DISCONNECT_CONNECTION_LOST = 10
SSH_DISCONNECT_BY_APPLICATION = 11
SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12
SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13
SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14
SSH_DISCONNECT_ILLEGAL_USER_NAME = 15
default_disconnect_messages = (
    "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT",
    "SSH_DISCONNECT_PROTOCOL_ERROR",
    "SSH_DISCONNECT_KEY_EXCHANGE_FAILED",
    "SSH_DISCONNECT_RESERVED",
    "SSH_DISCONNECT_MAC_ERROR",
    "SSH_DISCONNECT_COMPRESSION_ERROR",
    "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE",
    "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED",
    "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE",
    "SSH_DISCONNECT_CONNECTION_LOST",
    "SSH_DISCONNECT_BY_APPLICATION",
    "SSH_DISCONNECT_TOO_MANY_CONNECTIONS",
    "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER",
    "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE",
    "SSH_DISCONNECT_ILLEGAL_USER_NAME",
)

logger = logutil.get_logger(__name__)


class SSHError(Exception):
    """SSH 错误"""


class DisconnectError(SSHError):
    """断开连接"""

    def __init__(self, reason_id: int, description: str):
        self.reason_id = reason_id
        self.description = description


class UnsupportedError(SSHError):
    """未支持"""


class UnexpectedError(SSHError):
    """非预期行为"""


class ReadEOFError(SSHError):
    """read end of file"""


class BadRequestError(SSHError):
    """无效请求"""


class PacketTooLargeError(SSHError):
    """数据包太大"""


def _expect(cond: bool, msg: str):
    if not cond:
        raise UnexpectedError(msg)


def to_bytes(s: t.Union[str, bytes]) -> bytes:
    if not isinstance(s, bytes):
        return s.encode()
    return s


def to_str(s: t.Union[str, bytes]) -> str:
    if not isinstance(s, str):
        return s.decode()
    return s


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


# noinspection DuplicatedCode
class Message:
    """提供 SSH message 组装和解析的便利方法。
    数据类型定义 https://datatracker.ietf.org/doc/html/rfc4251

    """

    def __init__(self, data: t.Optional[bytes] = None):
        if data:
            self.bytes_io = io.BytesIO(data)
        else:
            self.bytes_io = io.BytesIO()

    def add_message_id(self, mid: int):
        b = bytes([mid])
        self.add_raw_bytes(b)

    def get_message_id(self) -> int:
        b = self.get_raw_bytes(1)
        return b[0]

    def is_eof(self):
        b = self.bytes_io.read(1)
        return b == b""

    def add_boolean(self, cond: bool):
        if cond:
            self.add_raw_bytes(b"\x01")
        else:
            self.add_raw_bytes(b"\x00")

    def get_boolean(self):
        b = self.get_raw_bytes(1)
        return b[0] != 0

    def add_uint32(self, n: int):
        b = struct.pack(">I", n)
        self.add_raw_bytes(b)

    def get_uint32(self):
        b = self.get_raw_bytes(4)
        length = struct.unpack(">I", b)[0]
        return length

    def add_uint64(self, n: int):
        b = struct.pack(">Q", n)
        self.add_raw_bytes(b)

    # 这里的 string 是 SSH 数据类型定义的 string
    def add_string(self, b: bytes):
        self.add_uint32(len(b))
        self.add_raw_bytes(b)

    def get_string(self) -> bytes:
        length = self.get_uint32()
        b = self.get_raw_bytes(length)
        return b

    def add_mpint(self, n: int):
        b = self.mpint(n)
        self.add_raw_bytes(b)

    def get_mpint(self):
        length = self.get_uint32()
        b = self.get_raw_bytes(length)
        return int.from_bytes(b, "big", signed=True)

    def add_name_list(self, *names: t.Union[str, bytes]):
        name_list = []
        for name in names:
            name_list.append(to_bytes(name))
        s = b",".join(name_list)
        self.add_string(s)

    def get_name_list(self) -> t.List[str]:
        length = self.get_uint32()
        b = self.get_raw_bytes(length)
        bs = b.split(b",")
        return [to_str(x) for x in bs]

    def add_mpint_bytes(self, b: bytes):
        """将 b 转为 mpint 后添加。
        b 会被解释为大端序的正整数。
        """
        b = self.bytes_to_mpint(b)
        self.add_raw_bytes(b)

    def add_raw_bytes(self, b: bytes):
        self.bytes_io.write(b)

    def get_raw_bytes(self, n: int):
        b = self.bytes_io.read(n)
        if len(b) != n:
            raise ReadEOFError("read end of file")
        return b

    def as_bytes(self) -> bytes:
        return self.bytes_io.getvalue()

    @staticmethod
    def is_pow_of_two(n: int) -> bool:
        """判断数字是否是 2 的指数倍。
        如 1 2 4 8 16 等等这些数据就是 2 的指数倍。
        """
        return n & (n - 1) == 0

    @staticmethod
    def mpint(num: int) -> bytes:
        """将整数转成 mpint 。
        mpint 为字节串，前四个字节表示后面字节数据的长度，后面的字节则是一个整数的大端序（网络序）字节表示。
        如果是正整数，字节表示的最高位必须是 0 ；负整数则是 1 。
        下面的例子是以 16 字节表示的

         value (hex)        representation (hex)
         -----------        --------------------
         0                  00 00 00 00
         9a378f9b2e332a7    00 00 00 08 09 a3 78 f9 b2 e3 32 a7
         // 80 的最高位为 1 ，所以给它前面补一个 \x00 字节
         80                 00 00 00 02 00 80
         // -1234 补码的十六进制就是 ed cc
         -1234              00 00 00 02 ed cc
         -deadbeef          00 00 00 05 ff 21 52 41 11

        概括来说，就是用最少的字节表示这个有符号数。
        比如有符号数 128 不能用两个字节表示，需要三个字节。
        """
        if num == 0:
            return b"\x00\x00\x00\x01\x00"
        n = abs(num)
        num_bytes = (n.bit_length() + 7) // 8
        # 拿到最高 8 位
        high_num = n >> ((num_bytes - 1) * 8)
        if high_num & 0b1000_0000 > 0 and not (num < 0 and (n & (n - 1) == 0)):
            # 最高位为 1 ，需要多加一个字节来表示
            # 但是存在特殊情况，就是类似 -128(0b1000_0000) 这样的，两个字节就可以了
            num_bytes += 1
        b = num.to_bytes(num_bytes, "big", signed=True)
        # return num_bytes.to_bytes(4, 'big') + b
        return struct.pack(">I", num_bytes) + b

    @staticmethod
    def bytes_to_mpint(b: bytes) -> bytes:
        """将 b 转为 mpint 格式。
        b 会被解释为大端序的正整数。
        """
        first = b[0]
        if first & 0b1000_0000:
            # 最高位为 1 ，前面多加一个 \x00 字节
            b = b"\x00" + b
        return struct.pack(">I", len(b)) + b


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
            key_size: 生成的 key 大小
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
    """curve25519-sha256 密钥交换算法"""

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
            SSH_MSG_KEX_ECDH_INIT,
        )
        self._q_c = init_message.get_string()
        # server reply SSH_MSG_KEX_ECDH_REPLY
        #   byte     SSH_MSG_KEX_ECDH_REPLY
        #   string   K_S, server's public host key
        #   string   Q_S, server's ephemeral public key octet string .
        #   string   the signature on the exchange hash
        self._k_s = self.host_key.get_k_s()
        reply_message = Message()
        reply_message.add_message_id(SSH_MSG_KEX_ECDH_REPLY)
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

        sig = self.host_key.do_sign(exchange_hash)
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
        sig_m.add_string(self.host_key.algo.encode())
        sig_m.add_string(rs_m.as_bytes())
        sig_b = sig_m.as_bytes()
        return sig_b

    def do_hash(self, b: bytes) -> bytes:
        return hashlib.sha256(b).digest()


class ServerHostKeyBase(abc.ABC):
    """代表服务器的密钥"""
    algo = ""

    @abc.abstractmethod
    def do_sign(self, data: bytes) -> bytes:
        """对数据进行签名"""
        raise NotImplementedError("do_sign")

    @abc.abstractmethod
    def get_k_s(self) -> bytes:
        """返回用于密钥交换部分的 K_S"""
        raise NotImplementedError("get_public_key")


class EcdsaSha2Nistp256HostKey(ServerHostKeyBase):
    """ecdsa-sha2-nistp256 算法"""

    algo = "ecdsa-sha2-nistp256"
    category = "nistp256"

    def __init__(self, key_directory: str):
        self.directory = pathlib.Path(key_directory)

        with open(self.directory / "ssh_host_ecdsa_key.pub", "rb") as f:
            pub_key_data = f.read()
        self.public_key = serialization.load_ssh_public_key(pub_key_data)

        with open(self.directory / "ssh_host_ecdsa_key", "rb") as f:
            private_key_data = f.read()
        self.private_key = serialization.load_ssh_private_key(private_key_data, None)

    def get_k_s(self) -> bytes:
        # 下面这些结构格式都是抓包来的，长度都是大端序的 4 个字节
        # Host key type length: 19
        # Host key type: ecdsa-sha2-nistp256
        # ECDSA elliptic curve identifier length: 8
        # ECDSA elliptic curve identifier: nistp256
        # ECDSA public key length: 65
        # ECDSA public key (Q)
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

    def do_sign(self, data: bytes) -> bytes:
        return self.private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256()),
        )


class PacketIOInterface(abc.ABC):
    """SSH packet 格式的读写接口
    格式可看 https://datatracker.ietf.org/doc/html/rfc4253#section-6
    """
    # 读写 packet 编号，从 0 开始计数
    read_seq_num: int
    write_seq_num: int

    @abc.abstractmethod
    def read_packet(self) -> bytes:
        raise NotImplementedError("read_packet")

    @abc.abstractmethod
    def config_read(self, read_seq_num: int):
        raise NotImplementedError("config_read")

    @abc.abstractmethod
    def write_packet(self, payload: bytes):
        raise NotImplementedError("write_packet")

    @abc.abstractmethod
    def config_write(self, write_seq_num: int):
        raise NotImplementedError("config_write")


class RawPacketIO(PacketIOInterface):
    # 从 go golang.org/x/crypto/ssh copy
    max_packet = 256 * 1024

    def __init__(self, sock: socket.socket):
        self._sock = sock
        # 读写数据大小（单位：字节）
        self._read_size = 0
        self._write_size = 0

        # 读写 packet 编号，从 0 开始计数
        self.read_seq_num = -1
        self.write_seq_num = -1

    def _read_full(self, n: int) -> bytes:
        """
        读满 n 字节数据
        """
        b = self._sock.recv(n)
        if len(b) != n:
            raise BadRequestError(f"can not read {n} size data")
        self._read_size += len(b)
        return b

    def _read(self, n: int) -> bytes:
        """
        读取最多 n 字节数据
        """
        b = self._sock.recv(n)
        self._read_size += len(b)
        return b

    def _write(self, b: bytes) -> int:
        """
        写入数据
        """
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

    def config_read(self, read_seq_num: int):
        pass

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

    def config_write(self, write_seq_num: int):
        pass


class Chacha20Poly1305PacketIO(RawPacketIO):
    """

    openssh 对 chacha20-poly1305 的说明
    https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.chacha20poly1305
    分成两个 key ，一个用来加密 packet 长度，一个加密数据
    """

    def __init__(self, sock: socket.socket, kex_result: KexResult):
        super().__init__(sock)

        self._kex_result = kex_result

        self._read_length_key = b""
        self._read_data_key = b""

        self._write_length_key = b""
        self._write_data_key = b""

    def read_packet(self) -> bytes:
        self.read_seq_num += 1
        # 先解密长度
        b = self._read_full(4)
        nonce = b"\x00" * 8 + struct.pack(">Q", self.read_seq_num)
        algorithm = algorithms.ChaCha20(self._read_length_key, nonce)
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
        algorithm = algorithms.ChaCha20(self._read_data_key, nonce)
        payload_cipher = Cipher(algorithm, mode=None)
        payload_encryptor = payload_cipher.encryptor()
        poly_key = payload_encryptor.update(b"\0" * 32)
        p = poly1305.Poly1305(poly_key)
        p.update(b + payload)
        p.verify(mac)
        # 解密数据
        nonce = b"\1" + b"\0" * 7 + struct.pack(">Q", self.read_seq_num)
        algorithm = algorithms.ChaCha20(self._read_data_key, nonce)
        payload_cipher = Cipher(algorithm, mode=None)
        payload_decryptor = payload_cipher.decryptor()
        decrypted = payload_decryptor.update(payload)
        print("decrypted", decrypted, len(decrypted))
        padding_length = decrypted[0]
        return decrypted[1:-padding_length]

    def config_read(self, read_seq_num: int):
        self.read_seq_num = read_seq_num
        if self._kex_result.side == SSHSide.server:
            # read: client to server
            key_tag = b"C"
        else:
            # read: server to client
            key_tag = b"D"
        key = self._kex_result.compute_key(64, key_tag)
        self._read_data_key = key[:32]
        self._read_length_key = key[32:]

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
        algorithm = algorithms.ChaCha20(self._write_length_key, nonce)
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
        algorithm = algorithms.ChaCha20(self._write_data_key, nonce)
        data_cipher = Cipher(algorithm, mode=None)
        data_encryptor = data_cipher.encryptor()
        et = data_encryptor.update(packet_data)
        buffer.append(et)
        # 计算 MAC
        nonce = b"\x00" * 8 + struct.pack(">Q", self.write_seq_num)
        algorithm = algorithms.ChaCha20(self._write_data_key, nonce)
        payload_cipher = Cipher(algorithm, mode=None)
        payload_encryptor = payload_cipher.encryptor()
        poly_key = payload_encryptor.update(b"\0" * 32)
        p = poly1305.Poly1305(poly_key)
        p.update(b"".join(buffer))
        mac = p.finalize()
        buffer.append(mac)
        packet = b"".join(buffer)
        self._write(packet)

    def config_write(self, write_seq_num: int):
        self.write_seq_num = write_seq_num
        if self._kex_result.side == SSHSide.server:
            # write: server to client
            key_tag = b"D"
        else:
            # write: client to server
            key_tag = b"C"
        key = self._kex_result.compute_key(64, key_tag)
        self._write_data_key = key[:32]
        self._write_length_key = key[32:]


class SSHServerTransport:
    """
    The Secure Shell (SSH) Transport Layer Protocol: https://datatracker.ietf.org/doc/html/rfc4253

    实现 SSH 传输层
    """

    # 这里的算法列表都是 copy 的 openssh 客户端发送的算法
    # 算法名称中的一些缩写解释
    #   nistp256 代表的使用的椭圆曲线类别，其他的 nistp384 等等同理
    #   curve25519 是另外一种椭圆曲线类别
    #   ec 表示椭圆曲线（英文 elliptic curve ）
    #   dh 表示 diffie-hellman 密钥交换算法
    #   sha2 算法名称中间的这个表示使用 sha2 哈希算法
    #   @xxx @ 符号表示这个算法由组织 xxx 实现，没有 @ 的都是标准算法名字
    #   cert-v01 表示这个 key 是一个证书，有数字签名验证（类似 https 使用的证书）
    #   ssh-rsa host key 都会有哈希算法，像这些没有指定的默认是 sha1
    kex_algorithms = (
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group-exchange-sha1",
        # 这个 ext-info-c 是表示扩展的意思，我们暂时不管
        # 'ext-info-c',
    )
    server_host_key_algorithms = (
        # 这些用证书的全部注释，没有证书
        # "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        # "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        # "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        # "ssh-ed25519-cert-v01@openssh.com",
        # "rsa-sha2-512-cert-v01@openssh.com",
        # "rsa-sha2-256-cert-v01@openssh.com",
        # "ssh-rsa-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-ed25519",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
        "ssh-dss",
    )
    encryption_algorithms = (
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    )
    mac_algorithms = (
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

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._sock.settimeout(60)

        # 经过测试发现这种方式可以很好地支持 readline ，可以应对客户端不同的数据长度
        self._rfile = self._sock.makefile("rb", -1)

        self.side = SSHSide.server

        # 双方交换协议版本的数据需要保存，后面有用
        self.server_version_data = b"SSH-2.0-boatland_0.1"
        self.client_version_data = b""
        # 双方交换算法的数据也需要保存
        self.server_algorithms_message: Message = (
            self._build_server_algorithms_message()
        )
        self.client_algorithms_message: Message = Message()

        # 协商后采用的算法
        self._adopted_algo = AdoptedAlgorithm()

        self.kex_result: t.Optional["KexResult"] = None
        self.session_id = b""

        self._packet_reader: PacketIOInterface = RawPacketIO(self._sock)
        self._packet_writer: PacketIOInterface = self._packet_reader

    def start(self):
        self.exchange_protocol_version()
        self.negotiate_algorithm()
        self.exchange_key()

        m = self.read_message(SSH_MSG_SERVICE_REQUEST)
        print("receive data", m.as_bytes())
        service = m.get_string()
        if service not in (b"ssh-userauth", b"ssh-connection"):
            raise DisconnectError(
                SSH_DISCONNECT_SERVICE_NOT_AVAILABLE,
                "unsupported service " + service.decode(),
            )

        m = Message()
        m.add_message_id(SSH_MSG_SERVICE_ACCEPT)
        m.add_string(service)
        self.write_message(m)

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
            reason_id = SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED
            raise DisconnectError(
                reason_id,
                default_disconnect_messages[reason_id],
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
        client_msg = self.read_message(SSH_MSG_KEXINIT)
        self.client_algorithms_message = client_msg
        client_msg.get_raw_bytes(16)
        # 协商算法过程如下
        # 遍历客户端传来的算法，找到第一个服务端也支持的
        adopted_algo = self._adopted_algo
        kex_algorithms = client_msg.get_name_list()
        _expect(len(kex_algorithms) > 0, "empty kex_algorithms")
        for algo in kex_algorithms:
            if algo in self.kex_algorithms:
                adopted_algo.kex = algo
                break

        server_host_key_algorithms = client_msg.get_name_list()
        _expect(len(server_host_key_algorithms) > 0, "empty server_host_key_algorithms")
        for algo in server_host_key_algorithms:
            if algo in self.server_host_key_algorithms:
                adopted_algo.server_host_key = algo
                break

        encryption_algorithms_client_to_server = client_msg.get_name_list()
        _expect(
            len(encryption_algorithms_client_to_server) > 0,
            "empty encryption_algorithms_client_to_server",
        )
        for algo in encryption_algorithms_client_to_server:
            if algo in self.encryption_algorithms:
                adopted_algo.encryption_cs = algo
                break

        encryption_algorithms_server_to_client = client_msg.get_name_list()
        _expect(
            len(encryption_algorithms_server_to_client) > 0,
            "empty encryption_algorithms_server_to_client",
        )
        for algo in encryption_algorithms_server_to_client:
            if algo in self.encryption_algorithms:
                adopted_algo.encryption_sc = algo
                break

        mac_algorithms_client_to_server = client_msg.get_name_list()
        _expect(
            len(mac_algorithms_client_to_server) > 0,
            "empty mac_algorithms_client_to_server",
        )
        for algo in mac_algorithms_client_to_server:
            if algo in self.mac_algorithms:
                adopted_algo.mac_cs = algo
                break

        mac_algorithms_server_to_client = client_msg.get_name_list()
        _expect(
            len(mac_algorithms_server_to_client) > 0,
            "empty mac_algorithms_server_to_client",
        )
        for algo in mac_algorithms_server_to_client:
            if algo in self.mac_algorithms:
                adopted_algo.mac_sc = algo
                break

        # chacha20-poly1305@openssh.com 不需要额外的 MAC
        if adopted_algo.encryption_cs == "chacha20-poly1305@openssh.com":
            adopted_algo.mac_cs = "<implicit>"
        if adopted_algo.encryption_sc == "chacha20-poly1305@openssh.com":
            adopted_algo.mac_sc = "<implicit>"

        compression_algorithms_client_to_server = client_msg.get_name_list()
        _expect(
            len(compression_algorithms_client_to_server) > 0,
            "empty compression_algorithms_client_to_server",
        )
        for algo in compression_algorithms_client_to_server:
            if algo in self.compression_algorithms:
                adopted_algo.compression_cs = algo
                break

        compression_algorithms_server_to_client = client_msg.get_name_list()
        _expect(
            len(compression_algorithms_server_to_client) > 0,
            "empty compression_algorithms_server_to_client",
        )
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

        # 发送服务端支持的算法消息
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
        curve25519 密钥交换的一些不同的地方
        https://datatracker.ietf.org/doc/html/rfc8731#section-3
        交换算法 curve25519-sha256
        """
        kex = Curve25519Sha256Kex(self, self.session_id)
        self.kex_result = kex.do_server_exchange()
        if not self.session_id:
            self.session_id = self.kex_result.session_id
        print("kex_result", self.kex_result)

        # 发送 SSH_MSG_NEWKEYS
        m = Message()
        m.add_message_id(SSH_MSG_NEWKEYS)
        self.write_message(m)
        new_packet_writer = Chacha20Poly1305PacketIO(self._sock, self.kex_result)
        new_packet_writer.config_write(self._packet_writer.write_seq_num)
        self._packet_writer = new_packet_writer

        # client 也会发送 SSH_MSG_NEWKEYS
        self.read_message(SSH_MSG_NEWKEYS)
        new_packet_reader = Chacha20Poly1305PacketIO(self._sock, self.kex_result)
        new_packet_reader.config_read(self._packet_reader.read_seq_num)
        self._packet_reader = new_packet_reader

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
        message.add_message_id(SSH_MSG_KEXINIT)
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
        # 本地测试暂时使用本地生成的 key
        return EcdsaSha2Nistp256HostKey("./etc/ssh")

    def read_message(self, expected_message_id: t.Optional[int] = None) -> "Message":
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


def main():
    server_address = ("127.0.0.1", 10022)
    server = socketserver.TCPServer(server_address, SSHTransportHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
