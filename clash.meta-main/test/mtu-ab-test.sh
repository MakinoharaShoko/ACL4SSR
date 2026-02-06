#!/bin/bash
# MTU A/B 测试脚本
# 用法: ./mtu-ab-test.sh [目标IP]

set -e

TARGET=${1:-1.1.1.1}
CONFIG="/Users/fl/.config/clash.meta/config.yaml"
RESULT_DIR="/tmp/mtu-test-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULT_DIR"

echo "===================="
echo "MTU A/B 测试"
echo "目标: $TARGET"
echo "结果目录: $RESULT_DIR"
echo "===================="

# 备份配置
cp "$CONFIG" "$CONFIG.bak"

run_test() {
    local mtu=$1
    local name=$2
    
    echo ""
    echo ">>> 测试 MTU=$mtu ($name)"
    echo "---"
    
    # 修改 MTU
    sed -i.tmp "s/mtu: [0-9]*/mtu: $mtu/" "$CONFIG"
    
    # 重启 mihomo（需要你的启动命令）
    echo "请手动重启 mihomo 然后按回车继续..."
    read -r
    
    sleep 3
    
    # 测试 1: Ping 延迟和丢包
    echo "1) Ping 测试 (100 包)..."
    ping -c 100 "$TARGET" 2>&1 | tee "$RESULT_DIR/ping_$name.txt" | tail -3
    
    # 测试 2: 下载速度 (用 curl)
    echo ""
    echo "2) 下载测试..."
    for i in 1 2 3; do
        echo -n "  第 $i 次: "
        curl -s -o /dev/null -w "%{speed_download}" \
            "https://speed.cloudflare.com/__down?bytes=10000000" | \
            awk '{printf "%.2f MB/s\n", $1/1024/1024}'
    done 2>&1 | tee "$RESULT_DIR/download_$name.txt"
    
    # 测试 3: tracepath PMTU (需要 root)
    echo ""
    echo "3) PMTU 发现..."
    traceroute -M "$TARGET" 2>&1 | head -5 | tee "$RESULT_DIR/pmtu_$name.txt" || echo "  (需要 root 或安装 traceroute)"
}

# 运行测试
run_test 1500 "mtu1500"
run_test 9000 "mtu9000"

# 恢复配置
mv "$CONFIG.bak" "$CONFIG"
echo ""
echo ">>> 测试完成！请检查结果："
echo "  $RESULT_DIR/"
echo ""
echo "手动对比两组数据："
echo "  - ping 丢包率和平均延迟"
echo "  - 下载速度"
echo "  - PMTU 值"
