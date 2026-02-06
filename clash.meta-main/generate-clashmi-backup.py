#!/usr/bin/env -S uv run
# /// script
# dependencies = ["pyyaml", "requests"]
# ///
"""
生成 Clash Mi 兼容的备份 zip（自包含，无需 patch）

核心逻辑:
  1. 从 proxy-providers 本地缓存读取节点
  2. base64 格式的订阅解析成静态 proxies
  3. 用 proxy-groups 的 filter/exclude-filter 正则展开成静态 proxies 列表
  4. 规则转换成 mrs 二进制格式（省 10x 内存）
  5. 生成可直接导入的 backup.zip

注意: Clash Mi 导入是完全替换，不是合并！
"""

import json
import yaml
import re
import base64
import zipfile
import urllib.parse
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime


def load_config(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def expand_rule_providers(rules: list, rule_providers: dict, ruleset_dir: Path, skip_providers: set = None) -> list:
    """展开 RULE-SET 规则为内联规则，skip_providers 里的不展开（用于跳过超大规则集）"""
    skip_providers = skip_providers or set()
    expanded = []
    
    for rule in rules:
        # 检查是否为 RULE-SET 规则（允许 RULE-SET 和逗号之间有空格）
        rule_stripped = rule.strip()
        if not rule_stripped.upper().startswith("RULE-SET"):
            expanded.append(rule)
            continue
        
        # 解析 RULE-SET,provider_name,target[,NO-RESOLVE]
        parts = [p.strip() for p in rule.split(",")]  # 去除空格
        provider_name = parts[1]
        target = parts[2]
        no_resolve = ",NO-RESOLVE" if len(parts) > 3 and "NO-RESOLVE" in parts[3].upper() else ""
        
        # 跳过指定的超大规则集
        if provider_name in skip_providers:
            print(f"⏭️  跳过 {provider_name}")
            continue
        
        # 查找 provider 配置
        provider = rule_providers.get(provider_name)
        if not provider:
            print(f"⚠️  未知 provider: {provider_name}")
            continue
        
        # 确定缓存文件路径
        cache_path = provider.get("path", "")
        if cache_path:
            cache_file = ruleset_dir.parent / cache_path.lstrip("./")
        else:
            cache_file = ruleset_dir / f"{provider_name}.yaml"
        
        if not cache_file.exists():
            print(f"⚠️  缓存不存在: {cache_file}")
            continue
        
        # 读取规则
        try:
            content = cache_file.read_text(encoding="utf-8")
            behavior = provider.get("behavior", "domain")
            fmt = provider.get("format", "yaml")
            
            if fmt == "text" or not content.strip().startswith("payload:"):
                # 纯文本格式：每行一条规则
                lines = [l.strip() for l in content.split("\n") if l.strip() and not l.startswith("#")]
                
                for line in lines:
                    if "," in line:
                        # 已有规则格式：DOMAIN,xxx 或 DOMAIN-SUFFIX,xxx
                        expanded.append(f"{line},{target}{no_resolve}")
                    else:
                        # 纯域名
                        expanded.append(f"DOMAIN-SUFFIX,{line},{target}{no_resolve}")
                print(f"📋 {provider_name}: {len(lines)} 条规则 → {target}")
            else:
                # YAML payload 格式
                data = yaml.safe_load(content)
                payload = data.get("payload", [])
                
                for item in payload:
                    if behavior == "domain":
                        expanded.append(f"DOMAIN-SUFFIX,{item},{target}{no_resolve}")
                    elif behavior == "ipcidr":
                        if ":" in item:
                            expanded.append(f"IP-CIDR6,{item},{target}{no_resolve}")
                        else:
                            expanded.append(f"IP-CIDR,{item},{target}{no_resolve}")
                    elif behavior == "classical":
                        if "," in item:
                            rule_parts = item.split(",")
                            rule_parts[-1] = target
                            expanded.append(",".join(rule_parts) + no_resolve)
                        else:
                            expanded.append(f"{item},{target}{no_resolve}")
                
                print(f"📋 {provider_name}: {len(payload)} 条规则 → {target}")
        except Exception as e:
            print(f"⚠️  解析失败 {cache_file}: {e}")
            continue
    
    return expanded


def convert_to_mrs(yaml_path: Path, behavior: str, output_path: Path) -> tuple[bool, str]:
    """将规则文件转换为 mrs 二进制格式
    
    Args:
        yaml_path: 源规则文件路径
        behavior: 原始 behavior (domain/ipcidr/classical)
        output_path: mrs 输出路径
    
    Returns:
        (成功与否, 实际使用的 behavior)
    
    mrs 只支持 domain 和 ipcidr，classical 规则会被解析：
    - DOMAIN,xxx → xxx (精确匹配)
    - DOMAIN-SUFFIX,xxx → .xxx (后缀匹配，加点号)
    - DOMAIN-KEYWORD,xxx → +xxx (关键字匹配，加+号)
    """
    try:
        content = yaml_path.read_text(encoding="utf-8")
        
        # 解析规则
        if content.strip().startswith("payload:"):
            data = yaml.safe_load(content)
            lines = data.get("payload", [])
        else:
            lines = [l.strip() for l in content.split("\n") if l.strip() and not l.startswith("#")]
        
        clean_lines = []
        has_process_rules = False
        
        for line in lines:
            upper = line.upper()
            
            # hosts 文件格式
            if line.startswith(("0.0.0.0", "127.0.0.1")):
                parts = line.split()
                if len(parts) >= 2:
                    clean_lines.append(f".{parts[1]}")  # 作为后缀匹配
            # PROCESS 规则 - iOS 不支持
            elif upper.startswith("PROCESS-"):
                has_process_rules = True
            # DOMAIN 精确匹配
            elif upper.startswith("DOMAIN,"):
                domain = line.split(",")[1].strip()
                clean_lines.append(domain)
            # DOMAIN-SUFFIX 后缀匹配
            elif upper.startswith("DOMAIN-SUFFIX,"):
                domain = line.split(",")[1].strip()
                clean_lines.append(f".{domain}")  # 加点号表示后缀
            # DOMAIN-KEYWORD 关键字匹配
            elif upper.startswith("DOMAIN-KEYWORD,"):
                keyword = line.split(",")[1].strip()
                clean_lines.append(f"+{keyword}")  # 加+号表示关键字
            # IP 类规则 - 只在 ipcidr behavior 时处理
            elif upper.startswith(("IP-CIDR,", "IP-CIDR6,")):
                if behavior == "ipcidr":
                    clean_lines.append(line.split(",")[1].strip())
            # 其他不支持的规则类型
            elif upper.startswith(("SRC-IP", "DST-PORT", "SRC-PORT", "GEOIP")):
                continue
            else:
                # 普通域名行（可能带引号）
                clean = line.strip("'\"")
                if clean:
                    clean_lines.append(f".{clean}" if not clean.startswith((".", "+", "*")) else clean)
        
        if not clean_lines:
            if has_process_rules:
                print(f"   ℹ️  规则全是 PROCESS-NAME（iOS 不支持）")
            return False, ""
        
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("\n".join(clean_lines))
            temp_txt = Path(f.name)
        
        # 确定转换 behavior
        convert_behavior = "ipcidr" if behavior == "ipcidr" else "domain"
        
        # 调用 mihomo 转换
        result = subprocess.run(
            ["nix-shell", "-p", "mihomo", "--run", f"mihomo convert-ruleset {convert_behavior} text {temp_txt} {output_path}"],
            capture_output=True, text=True, timeout=60
        )
        
        temp_txt.unlink()
        
        if output_path.exists() and output_path.stat().st_size > 0:
            return True, convert_behavior
        return False, ""
    except Exception as e:
        print(f"⚠️  mrs 转换失败: {e}")
        return False, ""


def parse_ss_link(link: str) -> dict | None:
    """解析 ss:// 链接为 proxy 配置"""
    try:
        # ss://base64#name 或 ss://method:password@server:port#name
        if "#" in link:
            main, name = link[5:].split("#", 1)
            name = urllib.parse.unquote(name)
        else:
            main, name = link[5:], "SS"
        
        # 尝试 base64 解码
        try:
            decoded = base64.b64decode(main + "===").decode()
            # method:password@server:port
            if "@" in decoded:
                method_pass, server_port = decoded.rsplit("@", 1)
                method, password = method_pass.split(":", 1)
                server, port = server_port.rsplit(":", 1)
            else:
                return None
        except:
            # 非 base64 格式: method:password@server:port
            if "@" in main:
                method_pass, server_port = main.rsplit("@", 1)
                method, password = method_pass.split(":", 1)
                server, port = server_port.rsplit(":", 1)
            else:
                return None
        
        return {
            "name": name,
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password,
            "udp": True
        }
    except:
        return None


def parse_vmess_link(link: str) -> dict | None:
    """解析 vmess:// 链接为 proxy 配置"""
    try:
        data = json.loads(base64.b64decode(link[8:] + "===").decode())
        return {
            "name": data.get("ps", "VMess"),
            "type": "vmess",
            "server": data.get("add", ""),
            "port": int(data.get("port", 443)),
            "uuid": data.get("id", ""),
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("type", "auto") if data.get("type") != "none" else "auto",
            "network": data.get("net", "tcp"),
            "tls": data.get("tls") == "tls",
            "udp": True
        }
    except:
        return None


def parse_subscription(content: str) -> tuple[list[dict], list[str], bool]:
    """
    解析订阅内容，返回 (proxies列表, 节点名列表, 是否YAML格式)
    """
    proxies = []
    names = []
    
    # 尝试解析为 YAML
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and "proxies" in data:
            proxies = data["proxies"]
            names = [n["name"] for n in proxies if "name" in n]
            return proxies, names, True
    except:
        pass
    
    # 尝试解析 base64 编码的链接列表
    try:
        decoded = base64.b64decode(content.strip() + "===").decode("utf-8")
        for line in decoded.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            proxy = None
            if line.startswith("ss://"):
                proxy = parse_ss_link(line)
            elif line.startswith("vmess://"):
                proxy = parse_vmess_link(line)
            # TODO: vless, trojan 等
            
            if proxy:
                proxies.append(proxy)
                names.append(proxy["name"])
    except:
        pass
    
    return proxies, names, False


def load_provider_nodes(providers: dict, cache_dir: Path) -> tuple[dict[str, list[str]], list[dict], list[str]]:
    """
    从本地缓存加载所有 provider 的节点
    返回: (节点名映射, 需要静态写入的proxies, 支持YAML的provider名列表)
    """
    node_names = {}
    static_proxies = []
    yaml_providers = []
    
    for name, p in providers.items():
        cache_file = cache_dir / f"{name}.yaml"
        if not cache_file.exists():
            print(f"⚠️  缓存不存在: {cache_file}")
            continue
        
        content = cache_file.read_text(encoding="utf-8")
        proxies, names, is_yaml = parse_subscription(content)
        
        node_names[name] = names
        static_proxies.extend(proxies)  # 所有节点都加入静态列表
        
        if is_yaml:
            yaml_providers.append(name)
            print(f"📦 {name}: {len(names)} 个节点 (YAML)")
        else:
            print(f"📦 {name}: {len(names)} 个节点 (base64→静态)")
    
    return node_names, static_proxies, yaml_providers


def expand_proxy_group(group: dict, all_nodes: dict[str, list[str]]) -> dict:
    """展开 use/filter 为静态 proxies 列表"""
    # 清理 YAML 锚点残留
    result = {k: v for k, v in group.items() if not k.startswith("<<")}
    
    # 如果没有 use，直接返回
    if "use" not in result:
        return result
    
    # 收集所有候选节点
    candidates = []
    for provider_name in result.get("use", []):
        candidates.extend(all_nodes.get(provider_name, []))
    
    # 应用 filter
    if flt := result.get("filter"):
        pattern = re.compile(flt, re.IGNORECASE)
        candidates = [n for n in candidates if pattern.search(n)]
    
    # 应用 exclude-filter
    if exc := result.get("exclude-filter"):
        pattern = re.compile(exc, re.IGNORECASE)
        candidates = [n for n in candidates if not pattern.search(n)]
    
    # 合并现有 proxies（如 DIRECT）
    existing = result.get("proxies", [])
    result["proxies"] = existing + candidates
    
    # 移除动态字段
    for key in ["use", "filter", "exclude-filter"]:
        result.pop(key, None)
    
    return result


def extract_rules(config: dict, expanded_groups: list) -> dict:
    """提取 diversion_template（App 层模板，非规则本身）"""
    # proxygroup-templates 给 App UI 用
    proxygroup_templates = []
    for g in expanded_groups:
        template = {
            "name": g.get("name", ""),
            "type": g.get("type", "select"),
            "proxies": g.get("proxies", []),
        }
        if icon := g.get("icon"):
            template["icon"] = icon
        proxygroup_templates.append(template)
    
    return {
        "rule-providers": [],  # 规则已在 local_config 里
        "rule-templates": [],  # 不使用模板
        "proxygroup-templates": proxygroup_templates
    }


def extract_proxies(config: dict) -> list:
    """提取静态 proxies（如阿里云杭州）"""
    return config.get("proxies", [])


# 规则大小分类（按条数）
RULE_SIZE_LIMITS = {
    "lite": 10000,    # 轻量版：<1万条
    "medium": 50000,  # 中等版：<5万条
    "full": None,     # 完整版：无限制
}


def generate_backup(config: dict, config_dir: Path, cache_dir: Path, icloud: Path, 
                    node_names: set, all_proxies: list, expanded_groups: list):
    """生成 Clash Mi 备份，自动合并所有 REJECT 规则集"""
    
    print(f"\n{'='*50}")
    print(f"📦 生成 Clash Mi 备份（合并 REJECT 规则）")
    print(f"{'='*50}")
    
    # 处理 rules
    rules = []
    for r in config.get("rules", []):
        if not r.startswith(("PROCESS-NAME", "PROCESS-PATH")):
            rules.append(r)
    
    # 转换 rule-providers
    ruleset_dir = config_dir / "ruleset"
    rule_providers_file = {}
    ruleset_files = {}
    tmp_mrs_dir = Path(tempfile.mkdtemp())
    skipped_providers = set()
    reject_rulesets_to_merge = {}  # REJECT 规则集
    
    for name, provider in config.get("rule-providers", {}).items():
        cache_path = provider.get("path", "")
        if cache_path:
            cache_file = config_dir / cache_path.lstrip("./")
        else:
            cache_file = ruleset_dir / f"{name}.yaml"
        
        if not cache_file.exists():
            continue
        
        # 如果已经是 mrs 格式，直接复制
        if provider.get("format") == "mrs":
            rule_providers_file[name] = {
                "type": "file",
                "behavior": provider.get("behavior", "domain"),
                "path": f"./profiles/ruleset/{name}.mrs",
                "format": "mrs",
            }
            ruleset_files[f"profiles/ruleset/{name}.mrs"] = cache_file.read_bytes()
            print(f"📋 {name}: mrs 直接复制 ({cache_file.stat().st_size//1024}KB)")
            continue
        
        # 计算规则条数
        content = cache_file.read_text(encoding="utf-8")
        if content.strip().startswith("payload:"):
            data = yaml.safe_load(content)
            rule_count = len(data.get("payload", []))
        else:
            rule_count = len([l for l in content.split("\n") if l.strip() and not l.startswith("#")])
        
        # 检查是否是 REJECT 规则（需要合并）
        is_reject = False
        for r in config.get("rules", []):
            if f"RULE-SET,{name}," in r or f"RULE-SET,{name} " in r:
                if ",REJECT" in r.upper():
                    is_reject = True
                break
        
        if is_reject:
            reject_rulesets_to_merge[name] = (cache_file, provider.get("behavior", "domain"), rule_count)
            skipped_providers.add(name)
            print(f"🔄 收集 {name}：{rule_count} 条（待合并）")
            continue
        
        behavior = provider.get("behavior", "domain")
        mrs_path = tmp_mrs_dir / f"{name}.mrs"
        success, actual_behavior = convert_to_mrs(cache_file, behavior, mrs_path)
        
        if success:
            rule_providers_file[name] = {
                "type": "file",
                "behavior": actual_behavior,
                "path": f"./profiles/ruleset/{name}.mrs",
                "format": "mrs",
            }
            ruleset_files[f"profiles/ruleset/{name}.mrs"] = mrs_path.read_bytes()
            
            original_size = cache_file.stat().st_size
            mrs_size = mrs_path.stat().st_size
            ratio = original_size / mrs_size if mrs_size > 0 else 0
            print(f"📋 {name}: {rule_count}条 ({original_size//1024}KB → {mrs_size//1024}KB, {ratio:.1f}x)")
        else:
            # 检查是否全是 PROCESS-NAME
            if content.strip().startswith("payload:"):
                rules_list = yaml.safe_load(content).get("payload", [])
            else:
                rules_list = [l.strip() for l in content.split("\n") if l.strip() and not l.startswith("#")]
            
            if all(r.upper().startswith("PROCESS-") for r in rules_list if r):
                skipped_providers.add(name)
                continue
    
    # 合并 REJECT 规则集
    if reject_rulesets_to_merge:
        print(f"\n🔀 合并 {len(reject_rulesets_to_merge)} 个 REJECT 规则集...")
        merged_domains = set()
        
        for name, (file_path, behavior, count) in reject_rulesets_to_merge.items():
            content = file_path.read_text(encoding="utf-8")
            
            # 解析规则
            if content.strip().startswith("payload:"):
                data = yaml.safe_load(content)
                lines = data.get("payload", [])
            else:
                lines = [l.strip() for l in content.split("\n") if l.strip() and not l.startswith("#")]
            
            before = len(merged_domains)
            for line in lines:
                upper = line.upper()
                if line.startswith(("0.0.0.0", "127.0.0.1")):
                    parts = line.split()
                    if len(parts) >= 2:
                        merged_domains.add(f".{parts[1].lower()}")
                elif upper.startswith("DOMAIN,"):
                    merged_domains.add(line.split(",")[1].strip().lower())
                elif upper.startswith("DOMAIN-SUFFIX,"):
                    merged_domains.add(f".{line.split(',')[1].strip().lower()}")
                elif upper.startswith("DOMAIN-KEYWORD,"):
                    merged_domains.add(f"+{line.split(',')[1].strip().lower()}")
                elif line.startswith("*."):
                    merged_domains.add(f".{line[2:].lower()}")
                elif not upper.startswith(("PROCESS-", "IP-", "SRC-", "DST-", "GEOIP")):
                    merged_domains.add(f".{line.lower()}")
            
            new = len(merged_domains) - before
            print(f"   + {name}: {count} 条 → 新增 {new} 条")
        
        # 转换合并结果为 mrs
        print(f"   = 合并去重后: {len(merged_domains)} 条")
        
        merged_txt = tmp_mrs_dir / "combined-reject.txt"
        merged_mrs = tmp_mrs_dir / "combined-reject.mrs"
        
        with open(merged_txt, "w") as f:
            f.write("\n".join(sorted(merged_domains)))
        
        result = subprocess.run([
            "nix-shell", "-p", "mihomo", "--run",
            f'mihomo convert-ruleset domain text "{merged_txt}" "{merged_mrs}"'
        ], capture_output=True, text=True, timeout=120)
        
        if merged_mrs.exists():
            rule_providers_file["combined-reject"] = {
                "type": "file",
                "behavior": "domain",
                "path": "./profiles/ruleset/combined-reject.mrs",
                "format": "mrs",
            }
            ruleset_files["profiles/ruleset/combined-reject.mrs"] = merged_mrs.read_bytes()
            
            mrs_size = merged_mrs.stat().st_size
            print(f"✅ combined-reject: {len(merged_domains)}条 → {mrs_size//1024}KB mrs")
    
    # 过滤和替换 rules
    filtered_rules = []
    combined_rule_added = False
    merged_names = set(reject_rulesets_to_merge.keys())
    
    for r in rules:
        skip = False
        
        # 检查是否是被合并的规则集
        for p in merged_names:
            if f"RULE-SET,{p}," in r or f"RULE-SET,{p} " in r or r.endswith(f"RULE-SET,{p}"):
                skip = True
                if not combined_rule_added and reject_rulesets_to_merge:
                    # 用 combined-reject 替代第一个被合并的规则
                    filtered_rules.append("RULE-SET,combined-reject,REJECT")
                    combined_rule_added = True
                break
        
        # 检查是否是被跳过的规则集（非合并）
        if not skip:
            for p in (skipped_providers - merged_names):
                if f"RULE-SET,{p}," in r or f"RULE-SET,{p} " in r or r.endswith(f"RULE-SET,{p}"):
                    skip = True
                    break
        
        if not skip:
            filtered_rules.append(r)
    
    shutil.rmtree(tmp_mrs_dir, ignore_errors=True)
    
    # 生成配置
    static_yaml = {
        "proxies": all_proxies,
        "proxy-groups": expanded_groups,
        "rule-providers": rule_providers_file,
        "rules": filtered_rules,
    }
    static_content = yaml.dump(static_yaml, allow_unicode=True, sort_keys=False)
    
    profiles_data = {
        "current_id": "local_config.yaml",
        "profiles": [{
            "id": "local_config.yaml",
            "name": "桌面迁移配置",
            "url": "",
            "update_interval": 0,
            "enabled": True,
        }]
    }
    
    # 生成 ZIP
    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    zip_path = icloud / f"ClashMi_{timestamp}.backup.zip"
    
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("profiles.json", json.dumps(profiles_data, ensure_ascii=False, indent=2))
        zf.writestr("profile_patchs.json", json.dumps({"current_id": "", "profile_patchs": []}, indent=2))
        zf.writestr("diversion_template.json", json.dumps(extract_rules(config, expanded_groups), ensure_ascii=False, indent=2))
        zf.writestr("profiles/", "")
        zf.writestr("profiles/ruleset/", "")
        zf.writestr("profiles/local_config.yaml", static_content)
        for filepath, content in ruleset_files.items():
            zf.writestr(filepath, content)
    
    size_kb = zip_path.stat().st_size / 1024
    print(f"✅ {zip_path.name} ({size_kb:.0f} KB)")
    print(f"   {len(rule_providers_file)} 个规则文件, {len(filtered_rules)} 条规则")
    return zip_path


def main():
    config_dir = Path(__file__).parent
    config_path = config_dir / "config.yaml"
    cache_dir = config_dir / "proxy_providers"
    
    if not config_path.exists():
        print(f"❌ 配置不存在: {config_path}")
        return 1
    
    config = load_config(config_path)
    
    # 加载所有 provider 的节点
    node_names, static_proxies, _ = load_provider_nodes(
        config.get("proxy-providers", {}), cache_dir
    )
    
    # 合并 config.yaml 里的静态 proxies
    all_proxies = config.get("proxies", []) + static_proxies
    
    # 展开 proxy-groups
    expanded_groups = []
    for g in config.get("proxy-groups", []):
        expanded = expand_proxy_group(g, node_names)
        expanded_groups.append(expanded)
        if "use" in g:
            print(f"🔄 {expanded['name']}: {len(expanded.get('proxies', []))} 个节点")
    
    # 输出到 iCloud
    icloud = Path.home() / "Library/Mobile Documents/iCloud~com~nebula~clashmi"
    icloud.mkdir(parents=True, exist_ok=True)
    
    # 清理旧备份
    for f in icloud.glob("ClashMi_*.backup.zip"):
        f.unlink()
        print(f"🗑️  清理: {f.name}")
    
    print(f"\n⚠️  跳过 PROCESS-NAME 规则（iOS 不支持）")
    
    # 生成备份：自动合并所有 REJECT 规则集
    generate_backup(config, config_dir, cache_dir, icloud,
                   node_names, all_proxies, expanded_groups)


if __name__ == "__main__":
    exit(main() or 0)
