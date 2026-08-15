#!/usr/bin/env python3
"""
HavocObscura - Havoc C2 Profile Generator
Generates customized .yaotl profiles for Havoc C2 framework evasion.

Based on PyObscura by dmcxblue, adapted for Havoc.
"""

import argparse
import logging
import os
import random
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

import color

VERSION = "1.0"

REQUEST_TIMEOUT = 30
REQUEST_SPEED_PRESETS = {
    "fast": (0.5, 1.5),
    "medium": (2, 4),
    "slow": (4, 8),
    "stealth": (8, 15),
}
DEFAULT_REQUEST_SPEED = "medium"
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

MAX_HEADER_VALUE_LENGTH = 240
MAX_URI_LENGTH = 64
MAX_URIS_PER_BLOCK = 5
MIN_URI_LENGTH = 3
MAX_URI_DISCOVERY_LINKS = 100

GET_URI_PATTERNS = [
    r'/[a-z0-9-]+/[a-z0-9-]+\.html?$',
    r'/[a-z0-9-]+/[a-z0-9-]+/?$',
    r'/[a-z0-9-]+\.(js|css|json|xml)$',
    r'/api/v\d+/[a-z0-9-]+/?$',
    r'/[a-z]{2}(-[a-z]{2})?/[a-z0-9-]+/?$',
]

EXCLUDED_URI_PATTERNS = [
    r'google', r'facebook', r'twitter', r'analytics', r'tracking',
    r'pixel', r'beacon', r'doubleclick', r'adsense',
    r'\.pdf$', r'\.zip$', r'\.exe$', r'mailto:', r'javascript:', r'^#',
]

PREFERRED_SERVER_HEADERS = [
    'content-type', 'server', 'x-powered-by', 'cache-control', 'vary',
    'x-frame-options', 'x-content-type-options', 'strict-transport-security',
    'content-security-policy', 'x-xss-protection',
]

EXCLUDED_HEADERS = [
    'date', 'age', 'expires', 'set-cookie', 'transfer-encoding',
    'content-length', 'content-encoding', 'connection', 'keep-alive',
    'x-request-id', 'x-correlation-id', 'x-trace-id', 'cf-ray', 'cf-cache-status',
    'alt-svc', 'report-to', 'nel', ':status',
]

OPSEC_SPAWN_PROCESSES = [
    ("C:\\\\Windows\\\\System32\\\\RuntimeBroker.exe", "C:\\\\Windows\\\\SysWOW64\\\\RuntimeBroker.exe"),
    ("C:\\\\Windows\\\\System32\\\\SearchProtocolHost.exe", "C:\\\\Windows\\\\SysWOW64\\\\SearchProtocolHost.exe"),
    ("C:\\\\Windows\\\\System32\\\\smartscreen.exe", "C:\\\\Windows\\\\SysWOW64\\\\WerFault.exe"),
    ("C:\\\\Windows\\\\System32\\\\dllhost.exe", "C:\\\\Windows\\\\SysWOW64\\\\dllhost.exe"),
    ("C:\\\\Windows\\\\System32\\\\svchost.exe", "C:\\\\Windows\\\\SysWOW64\\\\svchost.exe"),
    ("C:\\\\Windows\\\\System32\\\\wbem\\\\wmiprvse.exe", "C:\\\\Windows\\\\SysWOW64\\\\wbem\\\\wmiprvse.exe"),
]


@dataclass
class ProfileConfig:
    target_url: str
    output_file: str
    sleep: int = 10
    jitter: int = 30
    secure: bool = True
    port: int = 443
    operator: str = "operator"
    password: str = "changeme123"
    hosts: List[str] = field(default_factory=lambda: ["<YOUR_C2_HOST>"])
    trust_xff: bool = False
    kill_date: str = ""
    listener_name: str = ""
    smb_pipe: str = ""
    service_endpoint: str = ""
    service_password: str = ""
    webhook_url: str = ""
    uris: List[str] = field(default_factory=list)
    slow_mode: bool = False
    request_speed: str = "medium"
    autodiscover: bool = False


@dataclass
class TemplateData:
    uris: List[str]
    headers: List[Tuple[str, str]]
    response_headers: List[Tuple[str, str]]
    user_agent: str


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(message)s',
        handlers=[logging.StreamHandler()]
    )


def get_request_delay(speed: str) -> Tuple[float, float]:
    if speed in REQUEST_SPEED_PRESETS:
        return REQUEST_SPEED_PRESETS[speed]
    if '-' in speed:
        try:
            parts = speed.split('-')
            return (float(parts[0]), float(parts[1]))
        except (ValueError, IndexError):
            pass
    try:
        val = float(speed)
        return (val * 0.8, val * 1.2)
    except ValueError:
        return REQUEST_SPEED_PRESETS[DEFAULT_REQUEST_SPEED]


def slow_request(url: str, speed: str = "medium") -> Optional[requests.Response]:
    headers = {
        'User-Agent': DEFAULT_USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'sec-ch-ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }

    delay_range = get_request_delay(speed)
    delay = random.uniform(delay_range[0], delay_range[1])
    time.sleep(delay)

    session = requests.Session()
    try:
        response = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        return response
    except requests.RequestException as e:
        logging.warning(f"Request failed: {e}")
        return None


def fetch_http_response(url: str, slow: bool = False, speed: str = "medium") -> Optional[requests.Response]:
    if slow:
        return slow_request(url, speed)
    try:
        headers = {'User-Agent': DEFAULT_USER_AGENT}
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        return response
    except requests.RequestException as e:
        logging.warning(f"Request failed: {e}")
        return None


def extract_links_from_html(html: str, base_url: str) -> List[str]:
    links = []
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in href_pattern.finditer(html):
        href = match.group(1)
        if href.startswith('/'):
            links.append(href)
        elif href.startswith('http'):
            parsed = urlparse(href)
            base_parsed = urlparse(base_url)
            if parsed.netloc == base_parsed.netloc:
                links.append(parsed.path or '/')
    return list(set(links))[:MAX_URI_DISCOVERY_LINKS]


def is_uri_excluded(uri: str) -> bool:
    for pattern in EXCLUDED_URI_PATTERNS:
        if re.search(pattern, uri, re.IGNORECASE):
            return True
    return False


def score_uri_for_get(uri: str) -> int:
    score = 0
    for pattern in GET_URI_PATTERNS:
        if re.search(pattern, uri, re.IGNORECASE):
            score += 10
    if len(uri) > 10:
        score += 2
    if uri.count('/') >= 2:
        score += 3
    return score


def discover_uris(url: str, slow: bool = False, speed: str = "medium") -> List[str]:
    logging.info(f"  {color.blue('[*]')} Discovering URIs from {url}")
    response = fetch_http_response(url, slow, speed)
    if not response:
        return []

    links = extract_links_from_html(response.text, url)
    valid_uris = []

    for link in links:
        if is_uri_excluded(link):
            continue
        if len(link) < MIN_URI_LENGTH or len(link) > MAX_URI_LENGTH:
            continue
        valid_uris.append(link)

    scored = [(uri, score_uri_for_get(uri)) for uri in valid_uris]
    scored.sort(key=lambda x: x[1], reverse=True)

    selected = [uri for uri, _ in scored[:MAX_URIS_PER_BLOCK]]
    logging.info(f"  {color.green('[+]')} Discovered {len(selected)} URIs")
    return selected


def is_header_excluded(name: str) -> bool:
    name_lower = name.lower()
    for excluded in EXCLUDED_HEADERS:
        if excluded in name_lower:
            return True
    return False


def score_header(name: str) -> int:
    name_lower = name.lower()
    for i, preferred in enumerate(PREFERRED_SERVER_HEADERS):
        if preferred in name_lower:
            return len(PREFERRED_SERVER_HEADERS) - i
    return 0


def select_smart_headers(headers: Dict[str, str], max_count: int = 8) -> List[Tuple[str, str]]:
    filtered = []
    for name, value in headers.items():
        if is_header_excluded(name):
            continue
        if len(value) > MAX_HEADER_VALUE_LENGTH:
            value = value[:MAX_HEADER_VALUE_LENGTH]
        filtered.append((name, value, score_header(name)))

    filtered.sort(key=lambda x: x[2], reverse=True)
    return [(name, value) for name, value, _ in filtered[:max_count]]


def fetch_template_data(url: str, config: ProfileConfig) -> Optional[TemplateData]:
    logging.info(f"  {color.blue('[*]')} Fetching HTTP response from {url}")
    response = fetch_http_response(url, config.slow_mode, config.request_speed)
    if not response:
        return None

    uris = config.uris
    if config.autodiscover and not uris:
        uris = discover_uris(url, config.slow_mode, config.request_speed)
    if not uris:
        parsed = urlparse(url)
        uris = [parsed.path or "/"]

    response_headers = select_smart_headers(dict(response.headers), max_count=10)

    client_headers = [
        ("Accept", "application/json, text/plain, */*"),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate, br"),
        ("Cache-Control", "no-cache"),
    ]

    return TemplateData(
        uris=uris,
        headers=client_headers,
        response_headers=response_headers,
        user_agent=DEFAULT_USER_AGENT,
    )


def format_uris(uris: List[str]) -> str:
    lines = []
    for uri in uris:
        lines.append(f'            "{uri}",')
    return '\n'.join(lines)


def format_headers(headers: List[Tuple[str, str]]) -> str:
    lines = []
    for name, value in headers:
        value = value.replace('"', '\\"')
        lines.append(f'            "{name}: {value}",')
    return '\n'.join(lines)


def generate_profile(config: ProfileConfig, template_data: TemplateData) -> str:
    template_path = Path(__file__).parent / "sample.yaotl"
    template = template_path.read_text()

    spawn64, spawn32 = random.choice(OPSEC_SPAWN_PROCESSES)

    if not config.kill_date:
        kill_date = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d 23:59:59")
    else:
        kill_date = config.kill_date

    if not config.listener_name:
        parsed = urlparse(config.target_url)
        listener_name = f"HTTPS - {parsed.netloc}" if config.secure else f"HTTP - {parsed.netloc}"
    else:
        listener_name = config.listener_name

    hosts_str = ', '.join(f'"{h}"' for h in config.hosts)

    smb_block = ""
    if config.smb_pipe:
        smb_block = f'''
    Smb {{
        Name     = "SMB Pivot"
        PipeName = "{config.smb_pipe}"
    }}'''

    service_block = ""
    if config.service_endpoint:
        service_block = f'''
Service {{
    Endpoint = "{config.service_endpoint}"
    Password = "{config.service_password or 'service-password'}"
}}
'''

    webhook_block = ""
    if config.webhook_url:
        webhook_block = f'''
WebHook {{
    Discord {{
        Url = "{config.webhook_url}"
        AvatarUrl = "https://raw.githubusercontent.com/HavocFramework/Havoc/main/Assets/Havoc.png"
        User = "Havoc"
    }}
}}
'''

    replacements = {
        "%date%": datetime.now().strftime("%Y-%m-%d"),
        "%target%": config.target_url,
        "%operator%": config.operator,
        "%password%": config.password,
        "%sleep%": str(config.sleep),
        "%jitter%": str(config.jitter),
        "%trust_xff%": "true" if config.trust_xff else "false",
        "%spawn64%": spawn64,
        "%spawn32%": spawn32,
        "%listener_name%": listener_name,
        "%hosts%": hosts_str,
        "%port_bind%": str(config.port),
        "%port_conn%": str(config.port),
        "%secure%": "true" if config.secure else "false",
        "%kill_date%": kill_date,
        "%user_agent%": template_data.user_agent,
        "%uris%": format_uris(template_data.uris),
        "%headers%": format_headers(template_data.headers),
        "%response_headers%": format_headers(template_data.response_headers),
        "%smb_listener%": smb_block,
        "%service_block%": service_block,
        "%webhook_block%": webhook_block,
    }

    profile = template
    for placeholder, value in replacements.items():
        profile = profile.replace(placeholder, value)

    return profile


def validate_profile(profile: str, config: ProfileConfig) -> List[str]:
    warnings = []

    if config.sleep < 5:
        warnings.append(f"Sleep time {config.sleep}s is very low - high traffic volume")

    if config.jitter < 10:
        warnings.append(f"Jitter {config.jitter}% is low - traffic may appear too regular")

    if config.jitter > 100:
        warnings.append(f"Jitter {config.jitter}% exceeds 100% - will be clamped")

    if not config.secure:
        warnings.append("HTTP mode (not HTTPS) - traffic is unencrypted")

    for uri in config.uris:
        if len(uri) > MAX_URI_LENGTH:
            warnings.append(f"URI '{uri[:30]}...' exceeds max length ({MAX_URI_LENGTH})")

    return warnings


def print_banner():
    banner = f"""
{color.red('╦ ╦╔═╗╦  ╦╔═╗╔═╗╔═╗╔╗ ╔═╗╔═╗╦ ╦╦═╗╔═╗')}
{color.red('╠═╣╠═╣╚╗╔╝║ ║║  ║ ║╠╩╗╚═╗║  ║ ║╠╦╝╠═╣')}
{color.red('╩ ╩╩ ╩ ╚╝ ╚═╝╚═╝╚═╝╚═╝╚═╝╚═╝╚═╝╩╚═╩ ╩')}
    {color.yellow(f'Havoc C2 Profile Generator v{VERSION}')}
    {color.blue('Based on PyObscura by dmcxblue')}
"""
    print(banner)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="HavocObscura - Havoc C2 Profile Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-discover URIs from target
  python HavocObscura.py --url https://www.microsoft.com --autodiscover --outprofile microsoft.yaotl

  # Manual URIs with stealth mode
  python HavocObscura.py --url https://outlook.office.com --uris "/owa/service.svc /EWS/Exchange.asmx" \\
      --slow --request-speed stealth --outprofile outlook.yaotl --sleep 30 --jitter 40

  # Generate with SMB pivot listener
  python HavocObscura.py --url https://teams.microsoft.com --autodiscover --smb-pipe "msagent_47" \\
      --outprofile teams.yaotl
        """
    )

    parser.add_argument("--url", required=True, help="Target URL to mimic")
    parser.add_argument("--outprofile", required=True, help="Output profile filename")
    parser.add_argument("--uris", help="Space-separated URIs to use")
    parser.add_argument("--autodiscover", action="store_true", help="Auto-discover URIs from target")
    parser.add_argument("--slow", action="store_true", help="Use slow request mode (bot bypass)")
    parser.add_argument("--request-speed", default="medium", help="Request speed: fast/medium/slow/stealth or custom (e.g., 5 or 3-7)")
    parser.add_argument("--sleep", type=int, default=10, help="Sleep time in seconds (default: 10)")
    parser.add_argument("--jitter", type=int, default=30, help="Jitter percentage (default: 30)")
    parser.add_argument("--http", action="store_true", help="Use HTTP instead of HTTPS")
    parser.add_argument("--port", type=int, help="Listener port (default: 443 for HTTPS, 80 for HTTP)")
    parser.add_argument("--hosts", help="Comma-separated C2 hosts")
    parser.add_argument("--operator", default="operator", help="Operator username")
    parser.add_argument("--password", default="changeme123", help="Operator password")
    parser.add_argument("--trust-xff", action="store_true", help="Trust X-Forwarded-For header (for redirectors)")
    parser.add_argument("--kill-date", help="Kill date (YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--listener-name", help="Custom listener name")
    parser.add_argument("--smb-pipe", help="Add SMB listener with this pipe name")
    parser.add_argument("--service-endpoint", help="External C2 service endpoint")
    parser.add_argument("--service-password", help="External C2 service password")
    parser.add_argument("--webhook", help="Discord webhook URL for notifications")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()
    setup_logging(args.verbose)

    secure = not args.http
    port = args.port if args.port else (443 if secure else 80)
    hosts = [h.strip() for h in args.hosts.split(',')] if args.hosts else ["<YOUR_C2_HOST>"]
    uris = args.uris.split() if args.uris else []

    config = ProfileConfig(
        target_url=args.url,
        output_file=args.outprofile,
        sleep=args.sleep,
        jitter=args.jitter,
        secure=secure,
        port=port,
        operator=args.operator,
        password=args.password,
        hosts=hosts,
        trust_xff=args.trust_xff,
        kill_date=args.kill_date or "",
        listener_name=args.listener_name or "",
        smb_pipe=args.smb_pipe or "",
        service_endpoint=args.service_endpoint or "",
        service_password=args.service_password or "",
        webhook_url=args.webhook or "",
        uris=uris,
        slow_mode=args.slow,
        request_speed=args.request_speed,
        autodiscover=args.autodiscover,
    )

    logging.info(f"{color.blue('[*]')} Generating Havoc profile for {args.url}")
    logging.info(f"  {color.blue('[*]')} Sleep: {config.sleep}s, Jitter: {config.jitter}%")
    logging.info(f"  {color.blue('[*]')} Secure: {config.secure}, Port: {config.port}")

    template_data = fetch_template_data(args.url, config)
    if not template_data:
        logging.error(f"{color.red('[!]')} Failed to fetch data from {args.url}")
        sys.exit(1)

    logging.info(f"  {color.green('[+]')} Fetched {len(template_data.response_headers)} response headers")
    logging.info(f"  {color.green('[+]')} Using {len(template_data.uris)} URIs")

    warnings = validate_profile("", config)
    for warning in warnings:
        logging.warning(f"  {color.yellow('[!]')} {warning}")

    profile = generate_profile(config, template_data)

    output_path = Path(args.outprofile)
    output_path.write_text(profile)

    logging.info(f"{color.green('[+]')} Profile written to {output_path}")
    logging.info(f"{color.blue('[*]')} Test with: ./havoc server --profile {output_path} -v --debug")


if __name__ == "__main__":
    main()
