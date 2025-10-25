#!/bin/bash

rsync -avz --delete --exclude="**/bin/" --exclude="**/build/" --exclude=".git/" --exclude="*.log" --exclude="*.bak" --exclude="*.o" -e "ssh -p 2233" $PWD root@64.69.34.166:/root/

#ssh -p 2233 root@64.69.34.166 "cd hev-socks5-tunnel && make clean && make ENABLE_DEBUG=1 && python3 test.py --no-start-tunnel"
ssh -p 2233 root@64.69.34.166 "cd hev-socks5-tunnel && make clean&& python3 test.py"
