#!/usr/bin/env -S uv run
# /// script
# dependencies = ["requests", "pyyaml"]
# ///
"""
生成合并的 REJECT 规则 mrs 文件

从多个远程源下载广告/恶意域名列表，合并去重后转换为 mrs 二进制格式。
支持的格式：hosts、纯域名列表、Clash YAML payload、Clash text list
"""

import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import requests
import yaml


# 规则源配置：名称 -> (URL, 格式)
# 格式: hosts / domains / yaml / clash-text
SOURCES = {
    # 广告拦截
    "awavenue": (
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Clash.yaml",
        "yaml",
    ),
    "banchina": (
        "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanEasyListChina.list",
        "clash-text",
    ),
    "disconnect": (
        "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
        "domains",
    ),
    "privacy": (
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Privacy/Privacy.list",
        "clash-text",
    ),
    "reject": (
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
        "yaml",
    ),
    "hagezi-pro": (
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        "domains",
    ),
    "oisd-big": (
        "https://big.oisd.nl/domainswild2",
        "domains",
    ),
    # 安全/隐私
    "hijacking": (
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Hijacking/Hijacking.list",
        "clash-text",
    ),
    "pcdn": (
        "https://ruleset.skk.moe/Clash/non_ip/reject-no-drop.txt",
        "clash-text",
    ),
    # 恶意软件
    "urlhaus": (
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        "hosts",
    ),
    # 赌博
    "gambling": (
        "https://github.com/Sinfonietta/hostfiles/raw/master/gambling-hosts",
        "hosts",
    ),
    # 挖矿
    "nocoin": (
        "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
        "hosts",
    ),
}


def parse_hosts(content: str) -> set[str]:
    """解析 hosts 格式: 127.0.0.1 domain"""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("0.0.0.0", "127.0.0.1")):
            parts = line.split()
            if len(parts) >= 2 and parts[1] not in ("localhost", "localhost.localdomain"):
                domains.add(f".{parts[1].lower()}")
    return domains


def parse_domains(content: str) -> set[str]:
    """解析纯域名列表（每行一个域名，可能带 *.）"""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!", "[")):
            continue
        # 处理 *.domain.com 格式
        if line.startswith("*."):
            line = line[2:]
        domains.add(f".{line.lower()}")
    return domains


def parse_yaml(content: str) -> set[str]:
    """解析 Clash YAML payload 格式"""
    domains = set()
    try:
        data = yaml.safe_load(content)
        for item in data.get("payload", []):
            item = str(item).strip("'\"").lower()
            if item.startswith("+"):  # DOMAIN-KEYWORD
                domains.add(item)
            elif not item.startswith("."):
                domains.add(f".{item}")
            else:
                domains.add(item)
    except Exception as e:
        print(f"  ⚠️ YAML 解析失败: {e}")
    return domains


def parse_clash_text(content: str) -> set[str]:
    """解析 Clash text list 格式: DOMAIN-SUFFIX,xxx"""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith("DOMAIN,"):
            domains.add(line.split(",")[1].strip().lower())
        elif upper.startswith("DOMAIN-SUFFIX,"):
            domains.add(f".{line.split(',')[1].strip().lower()}")
        elif upper.startswith("DOMAIN-KEYWORD,"):
            domains.add(f"+{line.split(',')[1].strip().lower()}")
    return domains


def download_and_parse(name: str, url: str, fmt: str) -> tuple[str, set[str]]:
    """下载并解析规则，返回 (名称, 域名集合)"""
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    content = resp.text

    if fmt == "hosts":
        domains = parse_hosts(content)
    elif fmt == "domains":
        domains = parse_domains(content)
    elif fmt == "yaml":
        domains = parse_yaml(content)
    elif fmt == "clash-text":
        domains = parse_clash_text(content)
    else:
        return name, set()

    return name, domains


def convert_to_mrs(domains: set[str], output_path: Path) -> bool:
    """转换域名列表为 mrs 二进制格式"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(sorted(domains)))
        temp_txt = Path(f.name)

    try:
        if shutil.which("mihomo"):
            cmd = ["mihomo", "convert-ruleset", "domain", "text", str(temp_txt), str(output_path)]
        else:
            cmd = ["nix-shell", "-p", "mihomo", "--run",
                   f'mihomo convert-ruleset domain text "{temp_txt}" "{output_path}"']
        
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return output_path.exists() and output_path.stat().st_size > 0
    finally:
        temp_txt.unlink(missing_ok=True)


# JustMySocks 流量查询
JMS_API = "https://justmysocks6.net/members/getbwcounter.php?service=1221164&id=491e5d19-2e50-47dc-b3ae-6232b20419eb"

# 颜色
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
DIM = "\033[2m"
RESET = "\033[0m"


def check_jms_traffic():
    """查询并显示 JustMySocks 流量用量"""
    try:
        resp = requests.get(JMS_API, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        
        limit_gb = data["monthly_bw_limit_b"] / 1e9
        used_gb = data["bw_counter_b"] / 1e9
        reset_day = data["bw_reset_day_of_month"]
        used_pct = used_gb / limit_gb * 100
        
        # 计算时间进度
        today = datetime.now()
        day = today.day
        
        # 计算本周期已过天数和总天数
        if day >= reset_day:
            # 本月 reset_day 到今天
            days_passed = day - reset_day
            # 本周期从本月 reset_day 到下月 reset_day（约30天）
            total_days = 30
        else:
            # 上月 reset_day 到今天
            days_passed = (30 - reset_day) + day  # 简化计算
            total_days = 30
        
        time_pct = days_passed / total_days * 100
        
        # 比较用量进度和时间进度
        diff = used_pct - time_pct
        
        if diff < -10:
            color = GREEN
            status = "👍 用得慢"
        elif diff > 10:
            color = RED
            status = "⚠️ 用得快"
        else:
            color = YELLOW
            status = "正常"
        
        print(f"\n📊 JMS 流量: {color}{used_gb:.1f} GB{RESET} / {limit_gb:.0f} GB ({used_pct:.0f}%)")
        print(f"   时间进度: {time_pct:.0f}% | {status}")
        print(f"   每月 {reset_day} 号重置")
    except Exception as e:
        print(f"\n⚠️  流量查询失败: {e}")


def main():
    ruleset_dir = Path(__file__).parent / "ruleset"
    ruleset_dir.mkdir(exist_ok=True)
    output_path = ruleset_dir / "combined-reject.mrs"

    print("=" * 50)
    print("🔄 生成合并 REJECT 规则 (mrs)")
    print("=" * 50)

    # 并行下载所有规则
    t0 = time.time()
    all_domains: set[str] = set()
    results = []
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
        futures = {
            executor.submit(download_and_parse, name, url, fmt): name
            for name, (url, fmt) in SOURCES.items()
        }
        for future in as_completed(futures):
            results.append(future.result())
    t_download = time.time() - t0
    
    # 按名称排序后打印结果
    for name, domains in sorted(results):
        print(f"📥 {name:15s} {len(domains)} 条")
        all_domains.update(domains)

    print(f"\n📊 合并去重: {len(all_domains)} 条 (下载 {t_download:.1f}s)")

    # 转换为 mrs
    t0 = time.time()
    print("🔨 转换为 mrs...", end=" ", flush=True)
    if convert_to_mrs(all_domains, output_path):
        t_mrs = time.time() - t0
        size_kb = output_path.stat().st_size / 1024
        print(f"完成 ({size_kb:.0f} KB, {t_mrs:.1f}s)")
        print(f"✅ {output_path}")
        
        # 顺便查询流量
        check_jms_traffic()
        return 0
    else:
        print("失败")
        return 1


if __name__ == "__main__":
    exit(main())
