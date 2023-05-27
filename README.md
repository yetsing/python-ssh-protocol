# python-ssh-protocol

python ssh protocol implement

python 实现 ssh 协议，仅做学习交流使用，请不要用于生产环境。

## ssh server

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

讨论 ssh 的安全性

https://blog.stribik.technology/2015/01/04/secure-secure-shell.html


