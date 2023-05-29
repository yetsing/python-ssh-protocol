"""
测试 ssh server 支持的算法
"""
import collections
import socketserver
import subprocess
import threading
import time
import unittest

import ssh_server

AlgorithmTuple = collections.namedtuple(
    "AlgorithmTuple",
    ["kex", "host_key", "encryption", "mac"],
)


class TestSSHServerTransport(ssh_server.SSHServerTransport):
    def serve_userauth(self):
        # nothing to do
        pass

    def serve_connection(self) -> None:
        # nothing to do
        pass


class TestSSHTransportHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = TestSSHServerTransport(self.request)
        server.start()


class SSHServerAlgorithmTest(unittest.TestCase):
    def setUp(self) -> None:
        ssh_server.prepare_ssh_server()
        self.server_address = ("127.0.0.1", 10022)
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.TCPServer(
            self.server_address,
            TestSSHTransportHandler,
        )

    def algorithm_matrix(self):
        kex_algorithms = [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group14-sha256",
        ]
        server_host_key_algorithms = [
            "ecdsa-sha2-nistp256",
            "ssh-ed25519",
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ssh-rsa",
        ]
        encryption_algorithms = [
            "chacha20-poly1305@openssh.com",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
        ]
        mac_algorithms = [
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
        ]
        for kex_algo in kex_algorithms:
            for host_key_algo in server_host_key_algorithms:
                for encryption_algo in encryption_algorithms:
                    for mac_algo in mac_algorithms:
                        TestSSHServerTransport.kex_algorithms = (kex_algo,)
                        TestSSHServerTransport.support_server_host_key_algorithms = (
                            host_key_algo,
                        )
                        TestSSHServerTransport.encryption_algorithms = (
                            encryption_algo,
                        )
                        TestSSHServerTransport.mac_algorithms = (mac_algo,)
                        yield AlgorithmTuple(
                            kex_algo,
                            host_key_algo,
                            encryption_algo,
                            mac_algo,
                        )

    def start_server(self):
        self.server.serve_forever()
        print("server stopped")

    def test_support(self):
        t = threading.Thread(target=self.start_server, daemon=True)
        t.start()
        time.sleep(3)
        i = 0
        for algorithm_tuple in self.algorithm_matrix():
            print("\n\n=================", algorithm_tuple)
            subprocess.check_call(["ssh-keygen", "-R", "127.0.0.1"])
            # 这里没有用 check_output ，因为整个登录流程没有执行下去
            # 所以 ssh client 会异常状态退出，从而抛出异常，拿不到输出内容
            completed_process = subprocess.run(
                "ssh -oStrictHostKeyChecking=no -v test@127.0.0.1 -p 10022 2>&1",
                shell=True,
                capture_output=True,
                check=False,
            )
            output = completed_process.stdout
            self.assertIn(algorithm_tuple.kex.encode(), output)
            self.assertIn(algorithm_tuple.host_key.encode(), output)
            self.assertIn(algorithm_tuple.encryption.encode(), output)
            if (
                algorithm_tuple.encryption
                not in ssh_server.SSHServerTransport.aead_encryption_algorithms
            ):
                self.assertIn(algorithm_tuple.mac.encode(), output)
            self.assertIn(b"SSH2_MSG_SERVICE_ACCEPT received", output)
            i += 1
            time.sleep(1)
            # if i > 2048:
            #     break

        self.server.shutdown()
        t.join()
