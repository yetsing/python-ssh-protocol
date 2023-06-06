"""
ssh mac 支持
"""
import abc
import hashlib
import hmac
import secrets
import typing as t

try:
    import umac

    umac_support = True
except ImportError:
    umac_support = False


class MacInterface(abc.ABC):
    length = 0
    key_size = 0
    seq_bytes = 4
    is_etm = False

    def __init__(self, key: bytes):
        self.key = key

    @abc.abstractmethod
    def verify(self, message: bytes, mac: bytes) -> bool:
        raise NotImplementedError("verify")

    @abc.abstractmethod
    def calculate(self, message: bytes) -> bytes:
        raise NotImplementedError("calculate")


if umac_support:

    class UmacImpl(MacInterface):
        length = 8
        key_size = 16
        seq_bytes = 8
        umac_cls = umac.Umac

        def __init__(self, key: bytes):
            super().__init__(key)
            self.umac = self.umac_cls(self.key)

        def verify(self, message: bytes, mac: bytes) -> bool:
            nonce = message[:8]
            message = message[8:]
            got = self.umac.mac(message, nonce)
            return got == mac

        def calculate(self, message: bytes) -> bytes:
            nonce = message[:8]
            message = message[8:]
            got = self.umac.mac(message, nonce)
            return got

    class UmacEtmImpl(UmacImpl):
        is_etm = True

    class Umac128Impl(UmacImpl):
        length = 16
        umac_cls = umac.Umac128

    class Umac128EtmImpl(Umac128Impl):
        is_etm = True


class HmacImpl(MacInterface):
    hash_cls = None

    def verify(self, message: bytes, mac: bytes) -> bool:
        got = hmac.HMAC(self.key, message, self.hash_cls).digest()
        return secrets.compare_digest(got, mac)

    def calculate(self, message: bytes) -> bytes:
        got = hmac.HMAC(self.key, message, self.hash_cls).digest()
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
    if umac_support:
        mapping.update(
            {
                "umac-64@openssh.com": UmacImpl,
                "umac-64-etm@openssh.com": UmacEtmImpl,
                "umac-128-etm@openssh.com": Umac128EtmImpl,
            }
        )
    return mapping[algo]
