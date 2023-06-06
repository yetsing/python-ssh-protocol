# python-ssh-protocol

python ssh protocol implement

python 实现 ssh 协议，仅做学习交流使用，请不要用于生产环境。

暂时只实现了 ssh server 。

## ssh server

- 运行 server

```shell
python ssh_server.py
```

他会使用 ssk-keygen 在项目根目录下生成 host key 和 moduli ，位于 `etc/ssh` 下

使用 ssh 客户端连接

```shell
bash test_ssh_cli.sh

# 或者
ssh -v test@127.0.0.1 -p 10022
```

- umac 支持

需要编译 C 扩展

```shell
cd umac
python setup.py build_ext --inplace
cd ..
```

- 其他

关于 ssh 的流程可以找到博客文章说明，但是关于实现的细节就少之又少。

主要参考以下项目

[go ssh](https://pkg.go.dev/golang.org/x/crypto/ssh)

[python paramiko](https://github.com/paramiko/paramiko)

[openssh](https://github.com/openssh/openssh-portable)

讨论 ssh 的安全性

https://blog.stribik.technology/2015/01/04/secure-secure-shell.html

- 开发环境

Ubuntu 20.04

Python 3.7.16

OpenSSH_8.2p1 Ubuntu-4ubuntu0.7, OpenSSL 1.1.1f  31 Mar 2020
