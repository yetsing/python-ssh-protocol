"""
SSH 消息的组装和解析、消息 ID
"""
import enum
import io
import struct
import typing as t

from error import UnexpectedError


class SSHMessageID(enum.Enum):
    """
    rfc: https://datatracker.ietf.org/doc/html/rfc4250#section-4.1
    """

    DISCONNECT = 1
    IGNORE = 2
    UNIMPLEMENTED = 3
    DEBUG = 4
    SERVICE_REQUEST = 5
    SERVICE_ACCEPT = 6
    KEXINIT = 20
    NEWKEYS = 21
    KEX_ECDH_INIT = 30
    KEX_ECDH_REPLY = 31
    KEXDH_INIT = 30
    KEXDH_REPLY = 31
    # https://www.rfc-editor.org/rfc/rfc4419
    # 新的密钥交换消息 ID
    KEX_DH_GEX_REQUEST_OLD = 30
    KEX_DH_GEX_REQUEST = 34
    KEX_DH_GEX_GROUP = 31
    KEX_DH_GEX_INIT = 32
    KEX_DH_GEX_REPLY = 33
    USERAUTH_REQUEST = 50
    USERAUTH_FAILURE = 51
    USERAUTH_SUCCESS = 52
    USERAUTH_BANNER = 53
    USERAUTH_PK_OK = 60
    GLOBAL_REQUEST = 80
    REQUEST_SUCCESS = 81
    REQUEST_FAILURE = 82
    CHANNEL_OPEN = 90
    CHANNEL_OPEN_CONFIRMATION = 91
    CHANNEL_OPEN_FAILURE = 92
    CHANNEL_WINDOW_ADJUST = 93
    CHANNEL_DATA = 94
    CHANNEL_EXTENDED_DATA = 95
    CHANNEL_EOF = 96
    CHANNEL_CLOSE = 97
    CHANNEL_REQUEST = 98
    CHANNEL_SUCCESS = 99
    CHANNEL_FAILURE = 100


class SSHDisconnectReasonID(enum.IntEnum):
    HOST_NOT_ALLOWED_TO_CONNECT = 1
    PROTOCOL_ERROR = 2
    KEY_EXCHANGE_FAILED = 3
    RESERVED = 4
    MAC_ERROR = 5
    COMPRESSION_ERROR = 6
    SERVICE_NOT_AVAILABLE = 7
    PROTOCOL_VERSION_NOT_SUPPORTED = 8
    HOST_KEY_NOT_VERIFIABLE = 9
    CONNECTION_LOST = 10
    BY_APPLICATION = 11
    TOO_MANY_CONNECTIONS = 12
    AUTH_CANCELLED_BY_USER = 13
    NO_MORE_AUTH_METHODS_AVAILABLE = 14
    ILLEGAL_USER_NAME = 15


class SSHOpenReasonCode(enum.IntEnum):
    ADMINISTRATIVELY_PROHIBITED = 1
    CONNECT_FAILED = 2
    UNKNOWN_CHANNEL_TYPE = 3
    RESOURCE_SHORTAGE = 4


class SSHExtendedDataType(enum.IntEnum):
    STDERR = 1


def to_bytes(s: t.Union[str, bytes]) -> bytes:
    if not isinstance(s, bytes):
        return s.encode()
    return s


def to_str(s: t.Union[str, bytes]) -> str:
    if not isinstance(s, str):
        return s.decode()
    return s


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

    def add_message_id(self, mid: SSHMessageID):
        b = bytes([mid.value])
        self.add_raw_bytes(b)

    def get_message_id(self) -> SSHMessageID:
        b = self.get_raw_bytes(1)
        return SSHMessageID(b[0])

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
            raise UnexpectedError("read less data")
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
            # 这种特殊值有两个特点：小于 0 (num < 0) 、刚好是 2 的指数倍 (n & (n - 1) == 0)
            num_bytes += 1
        b = num.to_bytes(num_bytes, "big", signed=True)
        # return num_bytes.to_bytes(4, 'big') + b
        return struct.pack(">I", num_bytes) + b

    @staticmethod
    def bytes_to_mpint(b: bytes) -> bytes:
        """将 b 转为 mpint 格式。
        b 会被解释为大端序的正整数。
        """
        # 需要去除高位多余的 0x00
        i = 0
        for i in range(len(b)):
            if b[i] != 0:
                break
        b = b[i:]
        if b == b"":
            return b"\0\0\0\0"
        first = b[0]
        if first & 0b1000_0000:
            # 最高位为 1 ，前面多加一个 \x00 字节
            b = b"\x00" + b
        return struct.pack(">I", len(b)) + b
