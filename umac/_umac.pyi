class Umac:
    def __init__(self, key: bytes):
        """
        Args:
            key: 16 字节 key
        """
        ...
    def mac(self, message: bytes, nonce: bytes) -> bytes:
        """计算 mac

        Args:
            message: 消息
            nonce: 随机 8 字节
        Returns: 8 字节 mac
        """
        ...

class Umac128:
    def __init__(self, key: bytes):
        """
        Args:
            key: 16 字节 key
        """
        ...
    def mac(self, message: bytes, nonce: bytes) -> bytes:
        """计算 mac

        Args:
            message: 消息
            nonce: 随机 8 字节
        Returns: 16 字节 mac
        """
        ...
