#!/bin/bash

echo "=== 开始同步代码到远程服务器 ==="

# 同步代码到远程服务器
rsync -avz --delete --exclude="**/bin/" --exclude="**/build/" --exclude=".git/" --exclude="*.log" --exclude="*.bak" --exclude="*.o" -e "ssh -p 2233" $PWD root@64.69.34.166:/root/

echo "=== 开始远程编译和测试 ==="
#ssh -p 2233 root@64.69.34.166 "cd hev-socks5-tunnel && make clean && make ENABLE_DEBUG=1 && python3 test.py --no-start-tunnel"
ssh -p 2233 root@64.69.34.166 "cd hev-socks5-tunnel && make && python3 test.py"
REMOTE_EXIT_CODE=$?

if [ $REMOTE_EXIT_CODE -eq 0 ]; then
    echo "=== 远程测试成功，开始Git推送 ==="

    # 检查是否有未提交的更改
    if [ -n "$(git status --porcelain)" ]; then
        echo "发现未提交的更改，开始提交和推送..."

        # 添加所有更改（排除测试文件）
        git add src/
        git add Makefile
        git add README.md
        git add conf/
        git add rsync.sh

        # 提交更改
        COMMIT_MESSAGE="auto-fix: $(date '+%Y-%m-%d %H:%M:%S') - 智能代理GFW检测逻辑优化"
        git commit -m "$COMMIT_MESSAGE"

        # 推送到远程仓库
        echo "推送到远程仓库..."
        git push origin main

        if [ $? -eq 0 ]; then
            echo "✅ Git推送成功"
        else
            echo "❌ Git推送失败，请检查网络或权限"
            exit 1
        fi
    else
        echo "没有未提交的更改，跳过Git推送"
    fi

    echo "=== 部署和推送完成 ==="
else
    echo "❌ 远程测试失败，跳过Git推送"
    exit 1
fi
