#!/usr/bin/env python3
# /// script
# dependencies = ["pyyaml", "httpx[socks]", "rich", "maxminddb"]
# ///
"""
clash-probe: Clash/Mihomo proxy quality testing tool

Usage:
    uv run scripts/clash-probe.py [OPTIONS]

Features:
- Test proxy latency and download speed
- Auto-generate optimized proxy-groups for specific services
- Support multiple test sources (github, nix, npm, homebrew, etc.)
- Update config.yaml with best proxies per service
"""

import sys
import json
import time
import base64
import asyncio
import sqlite3
import random
import socket
import re
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote

import yaml
import httpx
import maxminddb
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live

console = Console()

# GeoIP database path
MMDB_PATH = Path.home() / ".config/clash.meta/country.mmdb"
_geoip_reader = None


def get_geoip_reader():
    """Lazy load GeoIP reader"""
    global _geoip_reader
    if _geoip_reader is None and MMDB_PATH.exists():
        try:
            _geoip_reader = maxminddb.open_database(str(MMDB_PATH))
        except Exception:
            pass
    return _geoip_reader

# Test URLs
LATENCY_URL = "https://cp.cloudflare.com/generate_204"

# fast.com API token (Netflix CDN)
FAST_COM_TOKEN = "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm"

# Speed test sources - categorized by use case
# Format: (name, url, test_type) where test_type is "speed" or "latency"
SPEED_TEST_SOURCES = {
    # === 大流量下载 - 测速度 ===
    "cachefly": ("https://cachefly.cachefly.net/10mb.test", "speed"),  # 10MB, global CDN baseline
    "github": ("https://github.com/cli/cli/releases/download/v2.63.2/gh_2.63.2_macOS_arm64.zip", "speed"),  # ~12MB
    "nodejs": ("https://nodejs.org/dist/v20.11.0/node-v20.11.0-darwin-arm64.tar.gz", "speed"),  # ~42MB
    "golang": ("https://go.dev/dl/go1.22.0.darwin-arm64.tar.gz", "speed"),  # ~67MB
    "nix": ("https://releases.nixos.org/nix/nix-2.19.3/nix-2.19.3-x86_64-darwin.tar.xz", "speed"),  # ~27MB
    "homebrew": ("https://github.com/Homebrew/brew/releases/download/4.2.5/Homebrew-4.2.5.pkg", "speed"),  # ~90MB
    "npm": ("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "speed"),  # ~1.5MB
    "pypi": ("https://files.pythonhosted.org/packages/cp312/n/numpy/numpy-2.2.1-cp312-cp312-macosx_14_0_arm64.whl", "speed"),  # ~5MB
    "crates": ("https://static.crates.io/crates/serde/serde-1.0.216.crate", "speed"),  # ~77KB
    
    # === 流媒体 - 测速度 ===
    "netflix": ("DYNAMIC", "speed"),  # fast.com Netflix CDN, URL obtained dynamically
    
    # === AI 服务 - 测延迟 ===
    "openai": ("https://api.openai.com/v1/models", "latency"),
    "anthropic": ("https://api.anthropic.com/v1/messages", "latency"),
    "deepseek": ("https://api.deepseek.com/v1/models", "latency"),
    "gemini": ("https://generativelanguage.googleapis.com/", "latency"),

    # === 其他 ===
    "cloudflare": ("https://cp.cloudflare.com/generate_204", "latency"),  # baseline
}

# Aliases for convenience
SOURCE_ALIASES = {
    "cf": "cachefly",
    "gh": "github",
    "node": "nodejs",
    "go": "golang",
    "hb": "homebrew",
    "nf": "netflix",
    "ai": "openai",
    "gpt": "openai",
    "claude": "anthropic",
    "ds": "deepseek",
}


def format_speed(kbps: float) -> str:
    """Format speed in human readable format"""
    if kbps >= 1024:
        return f"{kbps/1024:.1f}MB/s"
    else:
        return f"{kbps:.0f}KB/s"


# Country code to region mapping
COUNTRY_TO_REGION = {
    # 东亚
    "HK": "EA", "TW": "EA", "JP": "EA", "KR": "EA", "MO": "EA",
    # 中国大陆 (一般不会有，但以防万一)
    "CN": "CN",
    # 东南亚
    "SG": "SEA", "MY": "SEA", "TH": "SEA", "VN": "SEA", "PH": "SEA", "ID": "SEA", "MM": "SEA", "KH": "SEA", "LA": "SEA",
    # 南亚
    "IN": "SA", "PK": "SA", "BD": "SA", "LK": "SA",
    # 北美
    "US": "NA", "CA": "NA", "MX": "NA",
    # 南美
    "BR": "SA-L", "AR": "SA-L", "CL": "SA-L", "CO": "SA-L",
    # 西欧
    "GB": "EU-W", "DE": "EU-W", "FR": "EU-W", "NL": "EU-W", "BE": "EU-W", "IE": "EU-W", "AT": "EU-W", "CH": "EU-W",
    # 北欧
    "SE": "EU-N", "NO": "EU-N", "FI": "EU-N", "DK": "EU-N", "IS": "EU-N",
    # 东欧
    "PL": "EU-E", "UA": "EU-E", "RO": "EU-E", "CZ": "EU-E", "HU": "EU-E", "BG": "EU-E", "SK": "EU-E",
    # 南欧
    "IT": "EU-S", "ES": "EU-S", "PT": "EU-S", "GR": "EU-S",
    # 俄罗斯/中亚
    "RU": "RU", "KZ": "RU",
    # 中东
    "AE": "ME", "TR": "ME", "IL": "ME", "SA": "ME",
    # 大洋洲
    "AU": "OC", "NZ": "OC",
    # 非洲
    "ZA": "AF", "EG": "AF", "NG": "AF",
}


def resolve_host(hostname: str) -> str | None:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def detect_region(proxy: dict) -> tuple[str | None, str | None]:
    """
    Detect region for a proxy using GeoIP database.
    Returns (country_code, region_group)
    """
    reader = get_geoip_reader()
    if not reader:
        return None, None
    
    server = proxy.get("server")
    if not server:
        return None, None
    
    # Resolve hostname if needed
    ip = server
    if not server.replace(".", "").isdigit():
        ip = resolve_host(server)
        if not ip:
            return None, None
    
    try:
        result = reader.get(ip)
        if result and "country" in result:
            country = result["country"].get("iso_code")
            if country:
                region = COUNTRY_TO_REGION.get(country, "OTHER")
                return country, region
    except Exception:
        pass
    return None, None


def parse_clash_config(config_path: Path) -> dict:
    """Parse Clash config and extract proxy-providers with URLs"""
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    providers = {}
    if "proxy-providers" in config:
        for name, provider in config["proxy-providers"].items():
            if "url" in provider:
                providers[name] = {
                    "url": provider["url"],
                    "path": provider.get("path"),
                }
    return providers


def decode_base64(data: str) -> str:
    """Decode base64 with padding fix"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.b64decode(data).decode("utf-8")
    except Exception:
        return base64.urlsafe_b64decode(data).decode("utf-8")


def parse_ss_uri(uri: str) -> dict | None:
    """Parse ss:// URI"""
    try:
        if not uri.startswith("ss://"):
            return None
        rest = uri[5:]
        name = ""
        if "#" in rest:
            rest, name = rest.rsplit("#", 1)
            name = unquote(name)

        # Try base64 encoded format first
        try:
            decoded = decode_base64(rest.split("@")[0] if "@" in rest else rest)
            if "@" in decoded:
                method_pass, server_port = decoded.rsplit("@", 1)
                method, password = method_pass.split(":", 1)
                server, port = server_port.rsplit(":", 1)
            else:
                # Fully encoded
                parts = decoded.split("@")
                method_pass = parts[0]
                server_port = parts[1] if len(parts) > 1 else rest.split("@")[1]
                method, password = method_pass.split(":", 1)
                server, port = server_port.rsplit(":", 1)
        except Exception:
            # Handle partially encoded format
            if "@" in rest:
                encoded, server_port = rest.rsplit("@", 1)
                decoded = decode_base64(encoded)
                method, password = decoded.split(":", 1)
                server, port = server_port.rsplit(":", 1)
            else:
                return None

        return {
            "name": name or f"ss-{server}",
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password,
        }
    except Exception:
        return None


def parse_vmess_uri(uri: str) -> dict | None:
    """Parse vmess:// URI"""
    try:
        if not uri.startswith("vmess://"):
            return None
        data = decode_base64(uri[8:])
        config = json.loads(data)
        return {
            "name": config.get("ps", f"vmess-{config.get('add', 'unknown')}"),
            "type": "vmess",
            "server": config.get("add"),
            "port": int(config.get("port", 443)),
            "uuid": config.get("id"),
            "alterId": int(config.get("aid", 0)),
            "cipher": config.get("scy", "auto"),
            "tls": config.get("tls") == "tls",
            "network": config.get("net", "tcp"),
        }
    except Exception:
        return None


def parse_trojan_uri(uri: str) -> dict | None:
    """Parse trojan:// URI"""
    try:
        if not uri.startswith("trojan://"):
            return None
        parsed = urlparse(uri)
        name = unquote(parsed.fragment) if parsed.fragment else f"trojan-{parsed.hostname}"
        return {
            "name": name,
            "type": "trojan",
            "server": parsed.hostname,
            "port": parsed.port or 443,
            "password": unquote(parsed.username) if parsed.username else "",
        }
    except Exception:
        return None


def parse_subscription(content: str) -> list[dict]:
    """Parse subscription content (yaml/base64/uri list)"""
    proxies = []
    content = content.strip()

    # Try YAML format first
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and "proxies" in data:
            return data["proxies"]
        if isinstance(data, list):
            return data
    except Exception:
        pass

    # Try base64 decode
    try:
        decoded = decode_base64(content)
        content = decoded
    except Exception:
        pass

    # Parse URI list
    for line in content.split("\n"):
        line = line.strip()
        if not line:
            continue

        proxy = None
        if line.startswith("ss://"):
            proxy = parse_ss_uri(line)
        elif line.startswith("vmess://"):
            proxy = parse_vmess_uri(line)
        elif line.startswith("trojan://"):
            proxy = parse_trojan_uri(line)

        if proxy:
            proxies.append(proxy)

    return proxies


async def fetch_subscription(url: str, timeout: float = 30) -> list[dict]:
    """Fetch and parse subscription URL"""
    headers = {
        "User-Agent": "ClashX Meta/1.3.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return parse_subscription(resp.text)


def get_socks_url(proxy: dict, base_port: int = 7890) -> str | None:
    """
    Get SOCKS5 proxy URL.
    This requires Clash/Mihomo to be running with the proxy available.
    We use Clash's mixed-port as the SOCKS proxy.
    """
    # For testing through Clash, we use Clash's proxy port
    return f"socks5://127.0.0.1:{base_port}"


async def test_latency(proxy_name: str, clash_api: str = "127.0.0.1:9090", timeout: float = 10) -> tuple[float | None, str | None]:
    """Test proxy latency using Clash API"""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Use Clash API to test specific proxy
            url = f"http://{clash_api}/proxies/{proxy_name}/delay"
            resp = await client.get(url, params={"url": LATENCY_URL, "timeout": int(timeout * 1000)})
            if resp.status_code == 200:
                data = resp.json()
                return data.get("delay"), None
            else:
                return None, f"HTTP {resp.status_code}"
    except httpx.TimeoutException:
        return None, "timeout"
    except Exception as e:
        return None, str(e)


async def test_speed_single(client: httpx.AsyncClient, url: str, duration: float = 5) -> tuple[float | None, str | None]:
    """Test download speed for a single URL. Returns speed in KB/s."""
    try:
        start_time = time.time()
        total_bytes = 0

        async with client.stream("GET", url) as resp:
            if resp.status_code not in (200, 206):
                return None, f"HTTP {resp.status_code}"

            async for chunk in resp.aiter_bytes(chunk_size=8192):
                total_bytes += len(chunk)
                elapsed = time.time() - start_time
                if elapsed >= duration:
                    break

        elapsed = time.time() - start_time
        if elapsed > 0 and total_bytes > 0:
            speed_kbps = (total_bytes / 1024) / elapsed
            return speed_kbps, None
        return None, "no data"
    except httpx.TimeoutException:
        return None, "timeout"
    except Exception as e:
        return None, str(e)[:50]


async def get_fastcom_url(client: httpx.AsyncClient) -> str | None:
    """Get a fresh fast.com (Netflix CDN) download URL"""
    try:
        resp = await client.get(
            f"https://api.fast.com/netflix/speedtest/v2?https=true&token={FAST_COM_TOKEN}&urlCount=1"
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("targets"):
                return data["targets"][0]["url"]
    except Exception:
        pass
    return None


async def test_speed(proxy_name: str, clash_api: str = "127.0.0.1:9090", socks_port: int = 7890, duration: float = 5, large: bool = False) -> dict[str, tuple[float | None, str | None]]:
    """
    Test download speed through proxy using multiple URLs.
    Returns dict of {source: (speed_kbps, error)}.
    
    Args:
        large: If True, use large test files (10MB+) for more accurate results
    """
    results = {}
    # Select sources based on size preference
    if large:
        source_names = ["cachefly", "github", "nodejs", "golang", "nix", "homebrew"]
    else:
        source_names = ["cachefly", "npm"]
    
    urls = [(name, SPEED_TEST_SOURCES[name][0]) for name in source_names if name in SPEED_TEST_SOURCES]

    async with httpx.AsyncClient(
        timeout=duration + 30,
        proxy=f"socks5://127.0.0.1:{socks_port}",
        follow_redirects=True,
    ) as client:
        # Add fast.com URL for large tests (Netflix CDN, ~25MB)
        if large:
            fastcom_url = await get_fastcom_url(client)
            if fastcom_url:
                urls.append(("netflix", fastcom_url))
        
        for source, url in urls:
            speed, err = await test_speed_single(client, url, duration)
            results[source] = (speed, err)

    return results


class ProbeDB:
    """SQLite database for storing probe results"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS probe_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                provider TEXT NOT NULL,
                proxy_name TEXT NOT NULL,
                proxy_type TEXT,
                server TEXT,
                port INTEGER,
                latency_ms REAL,
                speed_kbps REAL,
                error TEXT
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON probe_results(timestamp)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_proxy ON probe_results(provider, proxy_name)
        """)
        self.conn.commit()

    def record(self, provider: str, proxy: dict, latency: float | None, speed: float | None, error: str | None):
        self.conn.execute(
            """
            INSERT INTO probe_results (timestamp, provider, proxy_name, proxy_type, server, port, latency_ms, speed_kbps, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                provider,
                proxy.get("name", "unknown"),
                proxy.get("type"),
                proxy.get("server"),
                proxy.get("port"),
                latency,
                speed,
                error,
            ),
        )
        self.conn.commit()

    def get_stats(self, provider: str | None = None, hours: int = 24) -> list[dict]:
        """Get statistics for proxies"""
        query = """
            SELECT
                provider,
                proxy_name,
                COUNT(*) as total_tests,
                AVG(latency_ms) as avg_latency,
                MIN(latency_ms) as min_latency,
                MAX(latency_ms) as max_latency,
                AVG(speed_kbps) as avg_speed,
                SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) as error_count
            FROM probe_results
            WHERE timestamp > datetime('now', ?)
        """
        params = [f"-{hours} hours"]

        if provider:
            query += " AND provider = ?"
            params.append(provider)

        query += " GROUP BY provider, proxy_name ORDER BY avg_latency"

        cursor = self.conn.execute(query, params)
        columns = [d[0] for d in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def close(self):
        self.conn.close()


async def probe_once(
    config_path: Path,
    db: ProbeDB,
    clash_api: str = "127.0.0.1:9090",
    socks_port: int = 7890,
    test_speed_flag: bool = False,
    speed_duration: float = 5,
    top_percent: int = 20,
):
    """
    Run one probe cycle.
    
    Strategy:
    1. Test latency for all proxies
    2. If speed test enabled: do small speed test for all working proxies
    3. Select top N% proxies (by latency + speed) for detailed large file test
    """
    providers = parse_clash_config(config_path)

    if not providers:
        console.print("[red]No proxy-providers found in config[/red]")
        return

    all_results = []

    # Phase 1: Latency test for all proxies
    console.print("\n[bold]=== Phase 1: Latency Test ===[/bold]")
    
    for provider_name, provider_info in providers.items():
        console.print(f"\n[cyan]Provider: {provider_name}[/cyan]")

        try:
            proxies = await fetch_subscription(provider_info["url"])
            console.print(f"  Found {len(proxies)} proxies")
        except Exception as e:
            console.print(f"  [red]Failed to fetch: {e}[/red]")
            continue

        for proxy in proxies:
            proxy_name = proxy.get("name", "unknown")
            latency, lat_err = await test_latency(proxy_name, clash_api)
            
            lat_str = f"{latency:.0f}ms" if latency else "[red]fail[/red]"
            if lat_err:
                console.print(f"  {proxy_name}: {lat_str} [dim]({lat_err})[/dim]")
            else:
                console.print(f"  {proxy_name}: {lat_str}")

            all_results.append({
                "provider": provider_name,
                "proxy": proxy,
                "proxy_name": proxy_name,
                "latency": latency,
                "error": lat_err,
                "speed_results": {},
            })

    if not test_speed_flag:
        # Just record latency results
        for r in all_results:
            db.record(r["provider"], r["proxy"], r["latency"], None, r["error"])
        return all_results

    # Phase 2: Small speed test for working proxies
    console.print("\n[bold]=== Phase 2: Speed Test (small, 1MB) ===[/bold]")
    
    working = [r for r in all_results if r["latency"] is not None]
    working.sort(key=lambda x: x["latency"])
    
    for r in working:
        proxy_name = r["proxy_name"]
        speed_results = await test_speed(proxy_name, clash_api, socks_port, speed_duration, large=False)
        r["speed_results"] = speed_results
        
        # Calculate average speed
        speeds = [spd for spd, err in speed_results.values() if spd is not None]
        r["avg_speed"] = sum(speeds) / len(speeds) if speeds else 0
        
        # Detect region using GeoIP
        country, region = detect_region(r["proxy"])
        r["country"] = country
        r["region"] = region
        
        speed_parts = []
        for src, (spd, err) in speed_results.items():
            if spd is not None:
                speed_parts.append(f"{src}:{format_speed(spd)}")
            else:
                speed_parts.append(f"{src}:[red]x[/red]")
        speed_str = " ".join(speed_parts) if speed_parts else "-"
        
        region_tag = f"[dim][{country or '??'}][/dim] " if country else ""
        console.print(f"  {region_tag}{proxy_name}: {r['latency']:.0f}ms {speed_str}")

    # Phase 3: Large speed test for top N% proxies PER REGION GROUP
    # This ensures we get the best proxies from each region, not just nearby ones
    console.print(f"\n[bold]=== Phase 3: Detailed Test (large, 10MB) - Top {top_percent}% per region ===[/bold]")
    
    # Group by region group (EA, SEA, NA, EU-W, etc.)
    by_region = {}
    for r in working:
        region = r["region"] or "OTHER"
        if region not in by_region:
            by_region[region] = []
        by_region[region].append(r)
    
    # Score and select top from each region
    # Skip percentage selection for small regions (< 5 proxies) - just test all
    MIN_REGION_SIZE = 5
    
    top_proxies = []
    for region, proxies in sorted(by_region.items()):
        # Score: lower latency better, higher speed better
        # Normalize: latency typically 50-500ms, speed typically 100-10000 KB/s
        proxies.sort(key=lambda x: (x["latency"] or 9999) / 100 - (x["avg_speed"] / 1000))
        
        if len(proxies) < MIN_REGION_SIZE:
            # Small region: just take the best one
            selected = proxies[:1]
            console.print(f"  [dim]{region}[/dim]: {len(proxies)} proxies (small, testing best 1)")
        else:
            # Large region: take top percentage
            top_count = max(1, len(proxies) * top_percent // 100)
            selected = proxies[:top_count]
            console.print(f"  [cyan]{region}[/cyan]: selected {len(selected)}/{len(proxies)}")
        
        top_proxies.extend(selected)
    
    console.print(f"\n  Total: {len(top_proxies)} proxies for detailed test\n")
    
    for r in top_proxies:
        proxy_name = r["proxy_name"]
        large_results = await test_speed(proxy_name, clash_api, socks_port, speed_duration * 2, large=True)
        
        # Merge results
        for src, val in large_results.items():
            r["speed_results"][f"{src}_large"] = val
        
        speed_parts = []
        for src, (spd, err) in large_results.items():
            if spd is not None:
                speed_parts.append(f"{src}:{format_speed(spd)}")
            else:
                speed_parts.append(f"{src}:[red]x[/red]")
        speed_str = " ".join(speed_parts) if speed_parts else "-"
        
        region_tag = f"[dim][{r['country'] or '??'}][/dim] " if r.get("country") else ""
        console.print(f"  [green]★[/green] {region_tag}{proxy_name}: {r['latency']:.0f}ms {speed_str}")

    # Record all results to database
    for r in all_results:
        best_speed = None
        for src, (spd, err) in r["speed_results"].items():
            if spd is not None and (best_speed is None or spd > best_speed):
                best_speed = spd
        db.record(r["provider"], r["proxy"], r["latency"], best_speed, r["error"])

    return all_results


async def probe_sample(
    config_path: Path,
    db: ProbeDB,
    clash_api: str = "127.0.0.1:9090",
    socks_port: int = 7890,
    speed_duration: float = 5,
    sample_percent: int = 10,
    sources: list[str] | None = None,
    custom_url: str | None = None,
):
    """
    Random sample mode: pick 10% of proxies and test speed.
    
    Args:
        sources: List of source names to test (e.g., ["github", "npm"]). If None, test all.
        custom_url: Custom URL to test instead of predefined sources.
    """
    providers = parse_clash_config(config_path)
    
    if not providers:
        console.print("[red]No proxy-providers found in config[/red]")
        return

    # Collect all proxies
    all_proxies = []
    for provider_name, provider_info in providers.items():
        try:
            proxies = await fetch_subscription(provider_info["url"])
            for p in proxies:
                all_proxies.append({"provider": provider_name, "proxy": p, "proxy_name": p.get("name", "unknown")})
        except Exception as e:
            console.print(f"[red]Failed to fetch {provider_name}: {e}[/red]")

    if not all_proxies:
        console.print("[red]No proxies found[/red]")
        return

    # Random sample
    sample_count = max(1, len(all_proxies) * sample_percent // 100)
    sampled = random.sample(all_proxies, sample_count)
    
    # Determine which sources to test
    # Resolve aliases
    if sources:
        resolved_sources = []
        for s in sources:
            resolved_sources.append(SOURCE_ALIASES.get(s, s))
        sources = resolved_sources
    
    if custom_url:
        test_sources = [("custom", custom_url, "speed")]
        console.print(f"\n[bold]=== Sample Mode: {sample_count} proxies, custom URL ===[/bold]")
        console.print(f"[dim]URL: {custom_url}[/dim]\n")
    elif sources:
        test_sources = []
        for name in sources:
            if name in SPEED_TEST_SOURCES:
                url, test_type = SPEED_TEST_SOURCES[name]
                test_sources.append((name, url, test_type))
        if not test_sources:
            console.print(f"[red]No matching sources. Available: {list(SPEED_TEST_SOURCES.keys())}[/red]")
            console.print(f"[dim]Aliases: {SOURCE_ALIASES}[/dim]")
            return
        console.print(f"\n[bold]=== Sample Mode: {sample_count} proxies, sources: {sources} ===[/bold]\n")
    else:
        # Default: test common download sources only (not all)
        default_sources = ["cachefly", "github", "nix", "npm", "netflix"]
        test_sources = [(name, *SPEED_TEST_SOURCES[name]) for name in default_sources if name in SPEED_TEST_SOURCES]
        console.print(f"\n[bold]=== Sample Mode: {sample_count}/{len(all_proxies)} proxies ===[/bold]")
        console.print(f"[dim]Sources: {[s[0] for s in test_sources]} (use --source for specific)[/dim]\n")

    results = []
    for i, item in enumerate(sampled, 1):
        proxy_name = item["proxy_name"]
        country, region = detect_region(item["proxy"])
        region_tag = f"[{country or '??'}]" if country else ""
        
        console.print(f"\n[cyan]({i}/{sample_count})[/cyan] {region_tag} {proxy_name}")
        
        # Latency test
        latency, lat_err = await test_latency(proxy_name, clash_api)
        if lat_err:
            console.print(f"  Latency: [red]fail ({lat_err})[/red]")
            continue
        console.print(f"  Latency: {latency:.0f}ms")
        
        # Speed/latency test per source
        speed_data = {}
        latency_data = {}
        async with httpx.AsyncClient(
            timeout=speed_duration + 30,
            proxy=f"socks5://127.0.0.1:{socks_port}",
            follow_redirects=True,
        ) as client:
            for source, url, test_type in test_sources:
                # Handle dynamic Netflix URL
                if url == "DYNAMIC":
                    url = await get_fastcom_url(client)
                    if not url:
                        console.print(f"  {source}: [red]x[/red] (failed to get URL)")
                        continue
                
                if test_type == "latency":
                    # Latency test - just measure response time
                    try:
                        start = time.time()
                        resp = await client.get(url, timeout=10)
                        elapsed = (time.time() - start) * 1000  # ms
                        latency_data[source] = elapsed
                        console.print(f"  {source}: {elapsed:.0f}ms")
                    except Exception as e:
                        console.print(f"  {source}: [red]x[/red] ({str(e)[:30]})")
                else:
                    # Speed test
                    speed, err = await test_speed_single(client, url, speed_duration)
                    speed_data[source] = speed
                    if speed:
                        console.print(f"  {source}: {format_speed(speed)}")
                    else:
                        console.print(f"  {source}: [red]x[/red] ({err})")
        
        results.append({
            "proxy_name": proxy_name,
            "country": country,
            "region": region,
            "latency": latency,
            "speeds": speed_data,
            "service_latencies": latency_data,
        })
    
    # Analysis
    if len(results) >= 2:
        console.print("\n[bold]=== Results Analysis ===[/bold]")
        
        # Speed analysis
        source_speeds = {}
        for r in results:
            for src, spd in r["speeds"].items():
                if spd:
                    if src not in source_speeds:
                        source_speeds[src] = []
                    source_speeds[src].append((r["proxy_name"], r["country"], spd))
        
        if source_speeds:
            table = Table(title="Download Speed by Source")
            table.add_column("Source", style="cyan")
            table.add_column("Avg", justify="right")
            table.add_column("Best Proxy", style="green")
            table.add_column("Best", justify="right")
            table.add_column("Worst", justify="right")
            
            for src, data in sorted(source_speeds.items(), key=lambda x: -sum(d[2] for d in x[1])/len(x[1]) if x[1] else 0):
                speeds = [d[2] for d in data]
                avg = sum(speeds) / len(speeds)
                best = max(data, key=lambda x: x[2])
                best_name = f"[{best[1] or '??'}] {best[0][:20]}"
                table.add_row(
                    src,
                    format_speed(avg),
                    best_name,
                    format_speed(max(speeds)),
                    format_speed(min(speeds)),
                )
            
            console.print(table)
        
        # Latency analysis  
        source_latencies = {}
        for r in results:
            for src, lat in r.get("service_latencies", {}).items():
                if lat:
                    if src not in source_latencies:
                        source_latencies[src] = []
                    source_latencies[src].append((r["proxy_name"], r["country"], lat))
        
        if source_latencies:
            table = Table(title="Service Latency")
            table.add_column("Service", style="cyan")
            table.add_column("Avg", justify="right")
            table.add_column("Best Proxy", style="green")
            table.add_column("Best", justify="right")
            table.add_column("Worst", justify="right")
            
            for src, data in sorted(source_latencies.items(), key=lambda x: sum(d[2] for d in x[1])/len(x[1]) if x[1] else 999):
                lats = [d[2] for d in data]
                avg = sum(lats) / len(lats)
                best = min(data, key=lambda x: x[2])
                best_name = f"[{best[1] or '??'}] {best[0][:20]}"
                table.add_row(
                    src,
                    f"{avg:.0f}ms",
                    best_name,
                    f"{min(lats):.0f}ms",
                    f"{max(lats):.0f}ms",
                )
            
            console.print(table)
    
    return results


def show_stats(db: ProbeDB, hours: int = 24):
    """Display statistics table"""
    stats = db.get_stats(hours=hours)

    if not stats:
        console.print("[yellow]No data available[/yellow]")
        return

    table = Table(title=f"Proxy Statistics (last {hours}h)")
    table.add_column("Provider", style="cyan")
    table.add_column("Proxy", style="white")
    table.add_column("Tests", justify="right")
    table.add_column("Avg Latency", justify="right")
    table.add_column("Min/Max", justify="right")
    table.add_column("Avg Speed", justify="right")
    table.add_column("Errors", justify="right")

    for s in stats:
        avg_lat = f"{s['avg_latency']:.0f}ms" if s['avg_latency'] else "-"
        min_max = f"{s['min_latency']:.0f}/{s['max_latency']:.0f}" if s['min_latency'] else "-"
        avg_speed = format_speed(s['avg_speed']) if s['avg_speed'] else "-"
        error_rate = f"{s['error_count']}/{s['total_tests']}"

        table.add_row(
            s["provider"],
            s["proxy_name"],
            str(s["total_tests"]),
            avg_lat,
            min_max,
            avg_speed,
            error_rate,
        )

    console.print(table)


async def run_continuous(
    config_path: Path,
    db: ProbeDB,
    interval: int = 300,
    clash_api: str = "127.0.0.1:9090",
    socks_port: int = 7890,
    test_speed_flag: bool = False,
    speed_duration: float = 5,
    top_percent: int = 20,
):
    """Run continuous monitoring"""
    console.print(f"[green]Starting continuous monitoring (interval: {interval}s)[/green]")
    console.print("Press Ctrl+C to stop\n")

    cycle = 0
    while True:
        cycle += 1
        console.print(f"\n[bold]=== Cycle {cycle} @ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===[/bold]")

        try:
            await probe_once(config_path, db, clash_api, socks_port, test_speed_flag, speed_duration, top_percent)
        except Exception as e:
            console.print(f"[red]Error in probe cycle: {e}[/red]")

        console.print(f"\n[dim]Next probe in {interval}s...[/dim]")
        await asyncio.sleep(interval)


# === Config Update Feature ===

# DEV 综合测速服务
# 用于计算综合开发场景得分
DEV_TEST_SERVICES = {
    "GitHub": "https://raw.githubusercontent.com/torvalds/linux/master/README",
    "NPM": "https://registry.npmjs.org/express",
    "PyPI": "https://pypi.org/pypi/requests/json",
    "Crates": "https://crates.io/api/v1/crates/serde",
    "Homebrew": "https://formulae.brew.sh/api/formula.json",
}

# DEV 相关的分流规则
DEV_RULES = [
    # GitHub
    "DOMAIN-SUFFIX,github.com",
    "DOMAIN-SUFFIX,githubusercontent.com",
    "DOMAIN-SUFFIX,githubassets.com",
    "DOMAIN-SUFFIX,github.io",
    # NPM
    "DOMAIN-SUFFIX,npmjs.org",
    "DOMAIN-SUFFIX,npmjs.com",
    "DOMAIN-SUFFIX,yarnpkg.com",
    # Python
    "DOMAIN-SUFFIX,pypi.org",
    "DOMAIN-SUFFIX,pythonhosted.com",
    "DOMAIN-SUFFIX,python.org",
    # Rust
    "DOMAIN-SUFFIX,crates.io",
    "DOMAIN-SUFFIX,rust-lang.org",
    # Homebrew
    "DOMAIN-SUFFIX,brew.sh",
    "DOMAIN-SUFFIX,homebrew.sh",
    # Go
    "DOMAIN-SUFFIX,golang.org",
    "DOMAIN-SUFFIX,go.dev",
    "DOMAIN-SUFFIX,proxy.golang.org",
    # Docker
    "DOMAIN-SUFFIX,docker.com",
    "DOMAIN-SUFFIX,docker.io",
    # Others
    "DOMAIN-SUFFIX,maven.org",
    "DOMAIN-SUFFIX,rubygems.org",
    "DOMAIN-SUFFIX,packagist.org",
    "DOMAIN-SUFFIX,nixos.org",
    "DOMAIN-SUFFIX,cachix.org",
]

# Sources that should have dedicated proxy groups
# Format: source_name -> (group_name, rule_patterns, providers)
# providers: list of provider names to use, or None for all
SOURCE_GROUPS = {
    # 综合开发组 - 使用 DOG
    "dev": ("_DEV", DEV_RULES, ["DOG"]),
}

# Default sources for --update-config (when no --source specified)
DEFAULT_SOURCES = ["dev"]

# Config markers
CONFIG_GROUPS_START = "# === CLASH-PROBE GROUPS START ==="
CONFIG_GROUPS_END = "# === CLASH-PROBE GROUPS END ==="
CONFIG_RULES_START = "# === CLASH-PROBE RULES START ==="
CONFIG_RULES_END = "# === CLASH-PROBE RULES END ==="


def calc_std_threshold(speeds: list[float], sigma: float = 1.0) -> float:
    """Calculate threshold as mean + sigma * std_dev"""
    if not speeds:
        return 0
    mean = sum(speeds) / len(speeds)
    variance = sum((s - mean) ** 2 for s in speeds) / len(speeds)
    std_dev = variance ** 0.5
    return mean + sigma * std_dev


async def test_all_proxies_for_source(
    config_path: Path,
    source: str,
    clash_api: str = "127.0.0.1:9090",
    socks_port: int = 7890,
    duration: float = 5,
    max_latency: int = 300,  # Only test proxies with latency < this
) -> list[dict]:
    """Test all proxies for a specific source and return results."""
    providers = parse_clash_config(config_path)
    if not providers:
        return []
    
    # Get source URL
    if source not in SPEED_TEST_SOURCES:
        console.print(f"[red]Unknown source: {source}[/red]")
        return []
    
    url, test_type = SPEED_TEST_SOURCES[source]
    
    # Collect all proxies
    all_proxies = []
    for provider_name, provider_info in providers.items():
        try:
            proxies = await fetch_subscription(provider_info["url"])
            for p in proxies:
                all_proxies.append({
                    "provider": provider_name,
                    "proxy": p,
                    "proxy_name": p.get("name", "unknown"),
                })
        except Exception as e:
            console.print(f"[red]Failed to fetch {provider_name}: {e}[/red]")
    
    if not all_proxies:
        return []
    
    # Phase 1: Quick latency filter
    console.print(f"  Phase 1: Latency filter (max {max_latency}ms)...")
    good_proxies = []
    for item in all_proxies:
        latency, lat_err = await test_latency(item["proxy_name"], clash_api)
        if not lat_err and latency and latency < max_latency:
            item["latency"] = latency
            good_proxies.append(item)
    
    console.print(f"  {len(good_proxies)}/{len(all_proxies)} proxies passed latency filter")
    
    if not good_proxies:
        return []
    
    # Define probe port
    probe_port = 17890

    # Sort by latency - test faster proxies first, limit to top 30
    good_proxies.sort(key=lambda x: x["latency"])
    if len(good_proxies) > 30:
        console.print(f"  Limiting to top 30 lowest latency proxies")
        good_proxies = good_proxies[:30]
    
    # Phase 2: Speed/service test on filtered proxies
    # We need to switch the GLOBAL proxy to each node before testing
    console.print(f"  Phase 2: Testing {source} on {len(good_proxies)} proxies...")
    
    results = []
    async with httpx.AsyncClient(timeout=30) as api_client:
        for i, item in enumerate(good_proxies, 1):
            proxy_name = item["proxy_name"]
            latency = item["latency"]
            
            # Switch CLASH_PROBE_TEST group to this node
            try:
                await api_client.put(
                    f"http://{clash_api}/proxies/CLASH_PROBE_TEST",
                    json={"name": proxy_name}
                )
            except Exception:
                pass  # May fail if group doesn't exist

            # Small delay for proxy switch to take effect
            await asyncio.sleep(0.1)
            
            async with httpx.AsyncClient(
                timeout=duration + 10,
                proxy=f"socks5://127.0.0.1:{probe_port}",
                follow_redirects=True,
            ) as client:
                actual_url = url
                if url == "DYNAMIC":
                    actual_url = await get_fastcom_url(client)
                    if not actual_url:
                        continue
                
                if test_type == "latency":
                    try:
                        start = time.time()
                        await client.get(actual_url, timeout=8)
                        elapsed = (time.time() - start) * 1000
                        results.append({
                            "provider": item["provider"],
                            "proxy_name": proxy_name,
                            "latency": latency,
                            "value": elapsed,
                            "type": "latency",
                        })
                        console.print(f"  [{i}/{len(good_proxies)}] {proxy_name}: {elapsed:.0f}ms")
                    except Exception as e:
                        console.print(f"  [{i}/{len(good_proxies)}] {proxy_name}: [red]fail[/red]")
                else:
                    speed, err = await test_speed_single(client, actual_url, duration)
                    if speed:
                        results.append({
                            "provider": item["provider"],
                            "proxy_name": proxy_name,
                            "latency": latency,
                            "value": speed,
                            "type": "speed",
                        })
                        console.print(f"  [{i}/{len(good_proxies)}] {proxy_name}: {format_speed(speed)}")
                    else:
                        console.print(f"  [{i}/{len(good_proxies)}] {proxy_name}: [red]fail[/red]")
    
    return results


async def test_all_proxies_for_dev(
    config_path: Path,
    clash_api: str = "127.0.0.1:9090",
    max_latency: int = 300,
    provider_filter: list[str] | None = None,
) -> tuple[list[dict], list[str]]:
    """
    Test all proxies for DEV services and return results with composite scores.
    
    Args:
        provider_filter: List of provider names to test. If None, test all.
    
    Returns:
        (results, providers_used): Tuple of results list and provider names used
    """
    providers = parse_clash_config(config_path)
    if not providers:
        return [], []
    
    # Filter providers if specified
    if provider_filter:
        providers = {k: v for k, v in providers.items() if k in provider_filter}
    
    # Collect all proxies from specified providers (只支持 URL 类型)
    all_proxies = []
    providers_used = []
    for provider_name, provider_info in providers.items():
        url = provider_info.get("url")
        if not url:
            continue  # 跳过没有 URL 的 provider
        try:
            proxies = await fetch_subscription(url)
            for p in proxies:
                all_proxies.append({
                    "provider": provider_name,
                    "proxy": p,
                    "proxy_name": p.get("name", "unknown"),
                })
            providers_used.append(provider_name)
            console.print(f"  Loaded {provider_name}: {len(proxies)} proxies")
        except Exception as e:
            console.print(f"[red]Failed to fetch {provider_name}: {e}[/red]")
    
    if not all_proxies:
        return [], providers_used
    
    console.print(f"\n[bold]DEV 综合测速[/bold]")
    console.print(f"  总节点数: {len(all_proxies)}")
    console.print(f"  测试服务: {', '.join(DEV_TEST_SERVICES.keys())}")
    
    # Phase 1: Quick latency filter
    console.print(f"\n  Phase 1: 延迟筛选 (max {max_latency}ms)...")
    good_proxies = []
    for item in all_proxies:
        latency, lat_err = await test_latency(item["proxy_name"], clash_api)
        if not lat_err and latency and latency < max_latency:
            item["latency"] = latency
            good_proxies.append(item)
    
    console.print(f"  {len(good_proxies)}/{len(all_proxies)} 节点通过延迟筛选")
    
    if not good_proxies:
        return []
    
    # Sort by latency and limit
    good_proxies.sort(key=lambda x: x["latency"])
    if len(good_proxies) > 40:
        console.print(f"  限制为延迟最低的 40 个节点")
        good_proxies = good_proxies[:40]
    
    probe_port = 17890
    
    # Phase 2: Test each service for each proxy
    console.print(f"\n  Phase 2: 多服务下载测速...")
    
    results = []
    async with httpx.AsyncClient(timeout=30) as api_client:
        for i, item in enumerate(good_proxies, 1):
            proxy_name = item["proxy_name"]
            latency = item["latency"]
            
            # Switch to this proxy
            try:
                await api_client.put(
                    f"http://{clash_api}/proxies/CLASH_PROBE_TEST",
                    json={"name": proxy_name}
                )
            except Exception:
                pass
            
            await asyncio.sleep(0.2)
            
            # Test all DEV services
            speeds = {}
            async with httpx.AsyncClient(
                timeout=15,
                proxy=f"socks5://127.0.0.1:{probe_port}",
                follow_redirects=True,
            ) as client:
                for svc_name, url in DEV_TEST_SERVICES.items():
                    try:
                        start = time.time()
                        resp = await client.get(url)
                        resp.raise_for_status()
                        elapsed = time.time() - start
                        speed = len(resp.content) / elapsed / 1024  # KB/s
                        speeds[svc_name] = speed
                    except Exception:
                        speeds[svc_name] = 0
            
            if any(speeds.values()):
                results.append({
                    "provider": item["provider"],
                    "proxy_name": proxy_name,
                    "latency": latency,
                    "speeds": speeds,
                })
                
                # Display progress
                avg_speed = sum(speeds.values()) / len(speeds)
                short_name = proxy_name[:30] + "..." if len(proxy_name) > 30 else proxy_name
                console.print(f"  [{i}/{len(good_proxies)}] {short_name:35} avg: {format_speed(avg_speed)}")
    
    return results, providers_used


def select_best_dev_proxies(results: list[dict], sigma: float = 1.0) -> list[str]:
    """
    Select best proxies for DEV based on composite score.
    
    Composite score = Σ(speed / mean_speed) / n
    This normalizes across services with different typical speeds.
    """
    if not results:
        return []
    
    # Calculate mean speed for each service
    service_means = {}
    for svc in DEV_TEST_SERVICES:
        speeds = [r["speeds"].get(svc, 0) for r in results if r["speeds"].get(svc, 0) > 0]
        if speeds:
            service_means[svc] = sum(speeds) / len(speeds)
        else:
            service_means[svc] = 1  # Avoid division by zero
    
    # Calculate composite score for each proxy
    for r in results:
        scores = []
        for svc, mean in service_means.items():
            speed = r["speeds"].get(svc, 0)
            if speed > 0 and mean > 0:
                scores.append(speed / mean)
        r["composite_score"] = sum(scores) / len(scores) if scores else 0
    
    # Calculate threshold
    scores = [r["composite_score"] for r in results if r["composite_score"] > 0]
    if not scores:
        return []
    
    mean = sum(scores) / len(scores)
    variance = sum((s - mean) ** 2 for s in scores) / len(scores)
    std_dev = variance ** 0.5
    threshold = mean + sigma * std_dev
    
    # Select proxies above threshold
    selected = [r for r in results if r["composite_score"] >= threshold]
    selected.sort(key=lambda x: -x["composite_score"])
    
    console.print(f"\n  综合得分统计:")
    console.print(f"    Mean: {mean:.2f}, StdDev: {std_dev:.2f}, Threshold: {threshold:.2f}")
    console.print(f"    选中 {len(selected)}/{len(results)} 节点 (sigma={sigma})")
    
    if selected:
        console.print(f"\n  最佳节点:")
        for r in selected[:5]:
            console.print(f"    {r['proxy_name']}: score={r['composite_score']:.2f}")
    
    return [r["proxy_name"] for r in selected]


def select_best_proxies(results: list[dict], sigma: float = 1.0) -> list[str]:
    """Select proxies above mean + sigma * std_dev threshold."""
    if not results:
        return []
    
    values = [r["value"] for r in results]
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    std_dev = variance ** 0.5
    
    is_latency = results[0]["type"] == "latency"
    
    if is_latency:
        # For latency: select those BELOW mean - sigma * std (lower is better)
        threshold = mean - sigma * std_dev
        selected = [r for r in results if r["value"] <= threshold]
        # Sort by latency ascending
        selected.sort(key=lambda x: x["value"])
    else:
        # For speed: select those ABOVE mean + sigma * std (higher is better)
        threshold = mean + sigma * std_dev
        selected = [r for r in results if r["value"] >= threshold]
        # Sort by speed descending
        selected.sort(key=lambda x: -x["value"])
    
    console.print(f"\n  Mean: {mean:.1f}, StdDev: {std_dev:.1f}, Threshold: {threshold:.1f}")
    console.print(f"  Selected {len(selected)}/{len(results)} proxies (sigma={sigma})")
    
    return [r["proxy_name"] for r in selected]


def build_filter_regex(proxy_names: list[str]) -> str:
    """Build a regex filter that matches the given proxy names.
    
    Note: Clash filter uses Go regex which is less strict.
    We don't escape chars because YAML double-quoted strings 
    don't support most escape sequences like \\. or \\-
    """
    if not proxy_names:
        return ".*"
    
    # Just join names with |, no escaping needed for Clash filter
    # The regex will match as substring anyway
    return "(" + "|".join(proxy_names) + ")"


def update_config_file(
    config_path: Path,
    groups: dict[str, tuple[str, list[str], list[str]]],  # source -> (group_name, proxy_names, providers_used)
) -> None:
    """Update config.yaml with new proxy-groups and rules."""
    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Build new groups section - maintain input order (not sorted)
    new_groups_lines = [CONFIG_GROUPS_START]
    junk_exclude_proxies = None
    
    for source, data in groups.items():
        group_name, proxy_names = data[0], data[1]
        providers_used = data[2] if len(data) > 2 else []
        
        if not proxy_names:
            continue
        
        # Special handling for JUNK - it's updated separately via regex replace
        if source == "_junk":
            junk_exclude_proxies = proxy_names
            continue
        
        filter_regex = build_filter_regex(proxy_names)
        # Truncate if too long
        if len(filter_regex) > 500:
            # Just use first N proxies
            filter_regex = build_filter_regex(proxy_names[:10])
        
        providers_str = ", ".join(providers_used) if providers_used else ""
        group_line = f'  - {{ name: {group_name}, type: url-test, url: http://cp.cloudflare.com/generate_204, interval: 300, tolerance: 50, use: [{providers_str}], filter: "{filter_regex}" }}'
        new_groups_lines.append(group_line)
    new_groups_lines.append(CONFIG_GROUPS_END)
    new_groups_text = "\n".join(new_groups_lines)
    
    # Build new rules section - maintain input order
    new_rules_lines = [CONFIG_RULES_START]
    for source, data in groups.items():
        group_name, proxy_names = data[0], data[1]
        if not proxy_names:
            continue
        if source in SOURCE_GROUPS:
            _, rule_patterns, _ = SOURCE_GROUPS[source]
            for pattern in rule_patterns:
                new_rules_lines.append(f"  - {pattern},{group_name}")
    new_rules_lines.append(CONFIG_RULES_END)
    new_rules_text = "\n".join(new_rules_lines)
    
    # Replace or insert groups section
    if CONFIG_GROUPS_START in content:
        # Replace existing
        pattern = re.compile(
            re.escape(CONFIG_GROUPS_START) + r".*?" + re.escape(CONFIG_GROUPS_END),
            re.DOTALL
        )
        content = pattern.sub(new_groups_text, content)
    else:
        # Insert after proxy-groups:
        # Find the line with "proxy-groups:" and insert after
        lines = content.split("\n")
        new_lines = []
        inserted = False
        for i, line in enumerate(lines):
            new_lines.append(line)
            if not inserted and line.strip().startswith("proxy-groups:"):
                # Insert our groups right after
                new_lines.append(new_groups_text)
                inserted = True
        content = "\n".join(new_lines)
    
    # Replace or insert rules section
    if CONFIG_RULES_START in content:
        pattern = re.compile(
            re.escape(CONFIG_RULES_START) + r".*?" + re.escape(CONFIG_RULES_END),
            re.DOTALL
        )
        content = pattern.sub(new_rules_text, content)
    else:
        # Insert after "rules:"
        lines = content.split("\n")
        new_lines = []
        inserted = False
        for i, line in enumerate(lines):
            new_lines.append(line)
            if not inserted and line.strip() == "rules:":
                new_lines.append(new_rules_text)
                inserted = True
        content = "\n".join(new_lines)
    
    # Update JUNK group filter if we have slow proxies to exclude
    if junk_exclude_proxies:
        # Build negative lookahead filter: (?!.*(slow1|slow2|...))
        # Also keep original exclusions like TW|France|Netherlands
        exclude_pattern = "|".join(junk_exclude_proxies[:20])  # Limit to 20 to avoid too long regex
        # Find and update JUNK line
        junk_pattern = re.compile(r'(name:\s*JUNK[^}]*filter:\s*")[^"]*(")')
        new_filter = f"(?!.*({exclude_pattern}|TW|France|Netherlands))"
        content = junk_pattern.sub(rf'\g<1>{new_filter}\g<2>', content)
    
    # Write back
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(content)
    
    console.print(f"\n[green]✓ Config updated: {config_path}[/green]")


async def update_config(
    config_path: Path,
    sources: list[str],
    db: "ProbeDB",
    clash_api: str = "127.0.0.1:9090",
    socks_port: int = 7890,
    duration: float = 5,
    sigma: float = 1.0,
):
    """Main function to update config with optimized proxy groups."""
    console.print(f"\n[bold]=== Updating Config with Optimized Groups ===[/bold]")
    console.print(f"Sources: {sources}")
    console.print(f"Sigma threshold: {sigma}")
    
    providers = parse_clash_config(config_path)
    provider_names = list(providers.keys())
    
    groups = {}
    
    for source in sources:
        if source not in SOURCE_GROUPS:
            console.print(f"[yellow]Warning: {source} has no predefined group/rules, skipping[/yellow]")
            continue
        
        group_name, _, provider_filter = SOURCE_GROUPS[source]
        console.print(f"\n[cyan]>>> Testing {source} -> {group_name}[/cyan]")
        
        # Use DEV composite testing for "dev" source
        if source == "dev":
            results, providers_used = await test_all_proxies_for_dev(
                config_path, clash_api, provider_filter=provider_filter
            )
            
            if not results:
                console.print(f"[yellow]No results for {source}[/yellow]")
                continue
            
            # Save to db
            for r in results:
                avg_speed = sum(r["speeds"].values()) / len(r["speeds"]) if r["speeds"] else 0
                db.record(
                    provider=r["provider"],
                    proxy={"name": r["proxy_name"]},
                    latency=r["latency"],
                    speed=avg_speed,
                    error=None,
                )
            
            # Select best using composite scoring
            best_proxies = []
            for test_sigma in [1.5, 1.25, 1.0, 0.75, 0.5, 0.375, 0.25, 0.125, 0]:
                selected = select_best_dev_proxies(results, test_sigma)
                if 3 <= len(selected) <= 10:
                    best_proxies = selected
                    break
                elif len(selected) >= 3 and (not best_proxies or len(selected) < len(best_proxies)):
                    best_proxies = selected
                elif len(selected) > 0 and not best_proxies:
                    best_proxies = selected
            
            # Fallback: take top 5 by composite score
            if not best_proxies and results:
                sorted_results = sorted(results, key=lambda x: -x.get("composite_score", 0))
                best_proxies = [r["proxy_name"] for r in sorted_results[:5]]
                console.print(f"  Fallback: taking top 5 proxies by composite score")
            
            if best_proxies:
                groups[source] = (group_name, best_proxies, providers_used)
                console.print(f"  [green]Selected:[/green] {len(best_proxies)} proxies for {group_name}")
            continue
        
        # Original single-source testing for non-dev sources
        results = await test_all_proxies_for_source(
            config_path, source, clash_api, socks_port, duration
        )
        
        if not results:
            console.print(f"[yellow]No results for {source}[/yellow]")
            continue
        
        # Save results to database for long-term analysis
        for r in results:
            speed = r["value"] if r["type"] == "speed" else None
            db.record(
                provider=r["provider"],
                proxy={"name": r["proxy_name"]},
                latency=r["latency"],
                speed=speed,
                error=None,
            )
        
        # Try different sigma values - start from high and go lower until we get 3-10 proxies
        best_sigma = 0.5
        best_proxies = []
        
        for test_sigma in [1.5, 1.25, 1.0, 0.75, 0.5, 0.375, 0.25, 0.125, 0]:
            selected = select_best_proxies(results, test_sigma)
            if 3 <= len(selected) <= 10:
                best_sigma = test_sigma
                best_proxies = selected
                break
            elif len(selected) >= 3 and (not best_proxies or len(selected) < len(best_proxies)):
                best_sigma = test_sigma
                best_proxies = selected
            elif len(selected) > 0 and not best_proxies:
                best_sigma = test_sigma
                best_proxies = selected
        
        # If still nothing, just take top 5
        if not best_proxies and results:
            is_latency = results[0]["type"] == "latency"
            sorted_results = sorted(results, key=lambda x: x["value"], reverse=not is_latency)
            best_proxies = [r["proxy_name"] for r in sorted_results[:5]]
            console.print(f"  Fallback: taking top 5 proxies")
        
        if best_proxies:
            groups[source] = (group_name, best_proxies, provider_filter or [])
            console.print(f"  [green]Selected (sigma={best_sigma}):[/green] {len(best_proxies)} proxies")
            for name in best_proxies[:5]:
                console.print(f"    - {name}")
            if len(best_proxies) > 5:
                console.print(f"    ... and {len(best_proxies) - 5} more")
    
    # JUNK 组直接使用 _10X（在 config.yaml 中已配置）
    # 不再动态测速
    
    if groups:
        update_config_file(config_path, groups)
        
        # Summary
        console.print("\n[bold]=== Summary ===[/bold]")
        for source, data in groups.items():
            group_name, proxy_names = data[0], data[1]
            if source == "_junk":
                console.print(f"  {group_name}: excluding {len(proxy_names)} slow proxies")
            else:
                console.print(f"  {group_name}: {len(proxy_names)} proxies")
    else:
        console.print("[yellow]No groups to update[/yellow]")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Clash/Mihomo proxy quality testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update config with ALL optimized proxy groups (default)
  uv run clash-probe.py --update-config

  # Update DEV group with composite testing
  uv run clash-probe.py --update-config --source dev

  # Quick sample test
  uv run clash-probe.py --sample --source github

  # Show statistics
  uv run clash-probe.py --stats

Default sources: dev (综合开发组)
        """,
    )
    parser.add_argument(
        "-c", "--config",
        type=Path,
        default=Path.home() / ".config/clash.meta/config.yaml",
        help="Path to Clash config file",
    )
    parser.add_argument(
        "-d", "--db",
        type=Path,
        default=Path.home() / ".config/clash.meta/probe.db",
        help="Path to SQLite database for storing results",
    )
    parser.add_argument(
        "--clash-api",
        default="127.0.0.1:9090",
        help="Clash external controller address",
    )
    parser.add_argument(
        "--socks-port",
        type=int,
        default=7890,
        help="Clash SOCKS/mixed port",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run continuous monitoring",
    )
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=300,
        help="Interval between probes in seconds (default: 300)",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show statistics instead of probing",
    )
    parser.add_argument(
        "-H", "--hours",
        type=int,
        default=24,
        help="Hours of history for statistics (default: 24)",
    )
    parser.add_argument(
        "--speed",
        action="store_true",
        help="Include download speed tests",
    )
    parser.add_argument(
        "--speed-duration",
        type=float,
        default=5,
        help="Duration of speed test in seconds (default: 5)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Percentage of top proxies for detailed (large file) test (default: 20%%)",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Random sample mode: test 10%% of proxies with speed sources",
    )
    parser.add_argument(
        "--sample-percent",
        type=int,
        default=10,
        help="Percentage of proxies to sample (default: 10%%)",
    )
    parser.add_argument(
        "--source",
        type=str,
        action="append",
        help="Speed test source(s). Can specify multiple. Use --list-sources to see all.",
    )
    parser.add_argument(
        "--url",
        type=str,
        help="Custom URL to test download speed",
    )
    parser.add_argument(
        "--list-sources",
        action="store_true",
        help="List all available test sources and exit",
    )
    parser.add_argument(
        "--update-config",
        action="store_true",
        help="Test all proxies for specified sources and update config.yaml with optimized groups",
    )
    parser.add_argument(
        "--sigma",
        type=float,
        default=1.0,
        help="Standard deviation threshold for selecting best proxies (default: 1.0)",
    )

    args = parser.parse_args()

    # Handle --list-sources
    if args.list_sources:
        console.print("\n[bold]Available Test Sources[/bold]\n")
        
        table = Table()
        table.add_column("Name", style="cyan")
        table.add_column("Alias", style="dim")
        table.add_column("Type", style="yellow")
        table.add_column("URL")
        
        # Build reverse alias map
        alias_map = {}
        for alias, name in SOURCE_ALIASES.items():
            if name not in alias_map:
                alias_map[name] = []
            alias_map[name].append(alias)
        
        for name, (url, test_type) in sorted(SPEED_TEST_SOURCES.items()):
            aliases = ", ".join(alias_map.get(name, []))
            display_url = url[:60] + "..." if len(url) > 60 else url
            table.add_row(name, aliases, test_type, display_url)
        
        console.print(table)
        console.print(f"\n[dim]Usage: clash-probe --sample --source github --source nix[/dim]")
        return

    if not args.config.exists():
        console.print(f"[red]Config file not found: {args.config}[/red]")
        sys.exit(1)

    db = ProbeDB(args.db)

    try:
        if args.stats:
            show_stats(db, args.hours)
        elif args.update_config:
            sources = args.source if args.source else DEFAULT_SOURCES
            asyncio.run(update_config(
                args.config,
                sources,
                db,
                args.clash_api,
                args.socks_port,
                args.speed_duration,
                args.sigma,
            ))
        elif args.sample:
            asyncio.run(probe_sample(
                args.config,
                db,
                args.clash_api,
                args.socks_port,
                args.speed_duration,
                args.sample_percent,
                args.source,
                args.url,
            ))
        elif args.continuous:
            asyncio.run(run_continuous(
                args.config,
                db,
                args.interval,
                args.clash_api,
                args.socks_port,
                args.speed,
                args.speed_duration,
                args.top,
            ))
        else:
            asyncio.run(probe_once(
                args.config,
                db,
                args.clash_api,
                args.socks_port,
                args.speed,
                args.speed_duration,
                args.top,
            ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user[/yellow]")
    finally:
        db.close()


if __name__ == "__main__":
    main()
