#!/usr/bin/env bash

ssh-keygen -R 127.0.0.1

ssh -oStrictHostKeyChecking=no -v test@127.0.0.1 -p 10022 2>&1
