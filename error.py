import typing as t

if t.TYPE_CHECKING:
    from message import SSHDisconnectReasonID


class SSHError(Exception):
    """SSH 错误"""


class DisconnectError(SSHError):
    """断开连接"""

    def __init__(self, reason_id: "SSHDisconnectReasonID", description: str):
        self.reason_id = reason_id
        self.description = description


class UnsupportedError(SSHError):
    """未支持"""


class UnexpectedError(SSHError):
    """非预期行为"""


class BadRequestError(SSHError):
    """无效请求"""


class PacketTooLargeError(SSHError):
    """数据包太大"""
