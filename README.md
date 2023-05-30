# python-ssh-protocol

python ssh protocol implement

python 实现 ssh 协议，仅做学习交流使用，请不要用于生产环境。

## ssh server

- 编译 C 扩展

```shell
cd umac
python setup.py build_ext --inplace
cd ..
```

- 运行 server

```shell
python ssh_server.py
```

记 `ssh_server.py` 所在文件夹为 `FILE_DIRECTORY`

他会使用 ssk-keygen 在 `FILE_DIRECTORY` 下生成 host key 和 moduli ，位于 `FILE_DIRECTORY/etc/ssh` 下

使用 ssh 客户端连接

```shell
ssh -v test@127.0.0.1 -p 10022
```

- 其他

关于 ssh 的流程可以找到博客文章说明，但是关于实现的细节就少之又少。

主要参考以下项目

[go ssh](https://pkg.go.dev/golang.org/x/crypto/ssh)

[python paramiko](https://github.com/paramiko/paramiko)

[openssh](https://github.com/openssh/openssh-portable)

讨论 ssh 的安全性

https://blog.stribik.technology/2015/01/04/secure-secure-shell.html


