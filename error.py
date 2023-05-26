import typing as t

if t.TYPE_CHECKING:
    from message import SSHDisconnectReasonID

default_disconnect_messages = (
    # 多加一个，这样 reason id 就跟数组的索引对上，不需要减一
    "unknown error",
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


class SSHError(Exception):
    """SSH 错误"""


class DisconnectError(SSHError):
    """断开连接"""

    def __init__(
            self, reason_id: "SSHDisconnectReasonID", description: t.Optional[str] = None
    ):
        self.reason_id = reason_id
        if description is None:
            description = default_disconnect_messages[reason_id]
        self.description = description


class UnsupportedError(SSHError):
    """未支持"""


class UnexpectedError(SSHError):
    """非预期行为"""


class BadRequestError(SSHError):
    """无效请求"""


class PacketTooLargeError(SSHError):
    """数据包太大"""
