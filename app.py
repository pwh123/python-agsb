import os
import json
import subprocess
import base64
import time
import requests
import random
import string
import OpenSSL
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from rich.console import Console

console = Console()

# 配置环境变量
ENV = {
    'UUID': os.getenv('UUID', '55e8ca56 - 8a0a - 4486 - b3f9 - b9b0d46638a9'),
    'CFIP': os.getenv('CFIP', '104.16.0.0'),
    'CFPORT': os.getenv('CFPORT', '8443'),
    'NAME': os.getenv('NAME','stim'),
    'FILE_PATH': os.getenv('FILE_PATH', './.cache'),
    'TUIC_PORT': os.getenv('TUIC_PORT', '28045'),
    'HY2_PORT': os.getenv('HY2_PORT', '28046'),
    'REALITY_PORT': os.getenv('REALITY_PORT', '60000'),
    'PORT': os.getenv('PORT', '7860'),
    'TELEGRAM_BOT_TOKEN': os.getenv('TELEGRAM_BOT_TOKEN', ''),
    'TELEGRAM_CHAT_ID': os.getenv('TELEGRAM_CHAT_ID', ''),
}


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content - type', 'text/html')
            self.end_headers()
            self.wfile.write(b'Hello World')
        elif self.path == '/sub':
            try:
                with open(f"{ENV['FILE_PATH']}/sub.txt", 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content - type', 'text/plain')
                self.end_headers()
                self.wfile.write(content)
            except:
                self.send_response(404)
                self.end_headers()


def send_telegram():
    TELEGRAM_BOT_TOKEN = ENV['TELEGRAM_BOT_TOKEN']
    TELEGRAM_CHAT_ID = ENV['TELEGRAM_CHAT_ID']
    FILE_PATH = Path(ENV['FILE_PATH'])
    NAME = ENV.get('NAME', 'Node')

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        console.print("\n[bold magenta]Telegram bot token or chat ID is empty. Skip pushing nodes to TG[/bold magenta]")
        return

    try:
        with open(FILE_PATH /'sub.txt', 'r', encoding='utf - 8') as file:
            message = file.read().strip()

        escaped_name = NAME
        for char in '_*[]()~`>#+=|{}.!-':
            escaped_name = escaped_name.replace(char, f'\\{char}')

        formatted_message = f"**{escaped_name}节点推送通知**\n```\n{message}\n```"

        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        params = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": formatted_message,
            "parse_mode": "MarkdownV2"
        }

        response = requests.post(url, params=params)

        if response.status_code == 200:
            console.print("\n[bold green]Telegram message sent successfully[/bold green]")
        else:
            console.print(f"\n[bold red]Failed to send Telegram message. Status code: {response.status_code}[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Failed to send Telegram message: {e}[/bold red]")


def generate_cert():
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    cert = OpenSSL.crypto.X509()
    cert.get_subject().CN = "bing.com"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key,'sha256')

    with open("cert.pem", "wb") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
    with open("private.key", "wb") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))


def download_files():
    arch = os.uname().machine
    if arch in ['arm', 'arm64', 'aarch64']:
        url = 'https://arm64.ssss.nyc.mn/sb'
    else:
        url = 'https://amd64.ssss.nyc.mn/sb'

    random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k = 6))
    try:
        response = requests.get(url, timeout = 30)
        response.raise_for_status()
        with open(random_name, 'wb') as f:
            f.write(response.content)
        os.chmod(random_name, 0o755)
        console.print(f"[bold green]Downloaded {random_name} successfully[/bold green]")
        return { 'web': random_name }
    except Exception as e:
        console.print(f"[bold red]Failed to download {random_name}: {str(e)}[/bold red]")
        return {}


def generate_config(file_map):
    config = {
        "log": {
            "disabled": False,
            "level": "info",
            "timestamp": True
        },
        "dns": {
            "servers": [
                {
                    "tag": "google",
                    "address": "tls://8.8.8.8"
                }
            ]
        },
        "inbounds": [
            {
                "tag": "tuic - in",
                "type": "tuic",
                "listen": "::",
                "listen_port": int(ENV['TUIC_PORT']),
                "users": [
                    {
                        "uuid": ENV['UUID'],
                        "password": "admin"
                    }
                ],
                "congestion_control": "bbr",
                "tls": {
                    "enabled": True,
                    "alpn": ["h3"],
                    "certificate_path": "cert.pem",
                    "key_path": "private.key"
                }
            },
            {
                "tag": "hysteria2 - in",
                "type": "hysteria2",
                "listen": "::",
                "listen_port": int(ENV['HY2_PORT']),
                "users": [
                    {
                        "password": ENV['UUID']
                    }
                ],
                "masquerade": "https://bing.com",
                "tls": {
                    "enabled": True,
                    "alpn": ["h3"],
                    "certificate_path": "cert.pem",
                    "key_path": "private.key"
                }
            },
            {
                "tag": "vless - reality - vesion",
                "type": "vless",
                "listen": "::",
                "listen_port": int(ENV['REALITY_PORT']),
                "users": [
                    {
                        "uuid": ENV['UUID'],
                        "flow": "xtls - rprx - vision"
                    }
                ],
                "tls": {
                    "enabled": True,
                    "server_name": "who.cx",
                    "reality": {
                        "enabled": True,
                        "handshake": {
                            "server": "who.cx",
                            "server_port": 443
                        },
                        "private_key": "",
                        "short_id": [""]
                    }
                }
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "direct", "tag": "direct - ipv4 - prefer - out", "domain_strategy": "prefer_ipv4"},
            {"type": "direct", "tag": "direct - ipv4 - only - out", "domain_strategy": "ipv4_only"},
            {"type": "direct", "tag": "direct - ipv6 - prefer - out", "domain_strategy": "prefer_ipv6"},
            {"type": "direct", "tag": "direct - ipv6 - only - out", "domain_strategy": "ipv6_only"},
            {
                "type": "wireguard",
                "tag": "wireguard - out",
                "server": "engage.cloudflareclient.com",
                "server_port": 2408,
                "local_address": [
                    "172.16.0.2/32",
                    "2606:4700:110:812a:4929:7d2a:af62:351c/128"
                ],
                "private_key": "gBthRjevHDGyV0KvYwYE52NIPy29sSrVr6rcQtYNcXA=",
                "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "reserved": [6, 146, 6]
            }
        ],
        "route": {
            "rule_set": [
                {
                    "tag": "geosite - netflix",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing - geosite/rule - set/geosite - netflix.srs",
                    "update_interval": "1d"
                },
                {
                    "tag": "geosite - openai",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/MetaCubeX/meta - rules - dat/sing/geo/geosite/openai.srs",
                    "update_interval": "1d"
                }
            ],
            "rules": [
                {
                    "ip_is_private": True,
                    "outbound": "direct"
                },
                {
                    "rule_set": ["geosite - openai"],
                    "outbound": "wireguard - out"
                },
                {
                    "rule_set": ["geosite - netflix"],
                    "outbound": "wireguard - out"
                }
            ],
            "final": "direct"
        },
        "experimental": {
            "cache_file": {
                "path": "cache.db",
                "cache_id": "mycacheid",
                "store_fakeip": True
            }
        }
    }

    with open('config.json', 'w') as f:
        json.dump(config, f, indent = 2)


def run_service_with_retry(cmd, service_name, max_retries = 3):
    for attempt in range(max_retries):
        process = subprocess.Popen(cmd.split(), stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
        time.sleep(2)

        if process.poll() is None:
            console.print(f"[bold green]{service_name} is running[/bold green]")
            return True
        else:
            if attempt < max_retries - 1:
                console.print(f"[bold yellow]{service_name} failed to start, retrying... ({attempt + 1}/{max_retries})[/bold yellow]")
                process.kill()
                time.sleep(1)
            else:
                console.print(f"[bold red]{service_name} failed to start after {max_retries} attempts[/bold red]")
    return False


def run_services(file_map):
    # 运行 web
    if 'web' in file_map and os.path.exists(file_map['web']):
        cmd = f'./{file_map["web"]} run -c config.json'
        run_service_with_retry(cmd, file_map['web'])
    time.sleep(1)

    if 'web' in file_map and os.path.exists(file_map['web']):
        os.remove(file_map['web'])


def get_ip_and_isp():
    ip = None
    try:
        ip = subprocess.check_output(['curl', '-s', 'ip.eooce.com'], timeout = 2).decode().strip()
        if ip.startswith('{'):
            ip = json.loads(ip).get('ip')
            if ':' in ip:
                ip = f'[{ip}]'
    except:
        pass

    if not ip:
        try:
            ip = subprocess.check_output(['curl', '-s', 'ip.sb'], timeout = 2).decode().strip()
            if ':' in ip:
                ip = f'[{ip}]'
        except:
            ip = "ip not found"

    if not ip or ip.startswith('<'):
        ip = "ip not found"

    try:
        meta = requests.get('https://speed.cloudflare.com/meta', timeout = 2).json()
        isp = f"{meta['colo']}-{meta['asOrganization']}".replace(' ', '_')
    except:
        isp = "unknown"

    return ip, isp


def generate_subscription(ip, isp):
    subscription_lines = []

    if ENV['HY2_PORT'] != '50000':
        hysteria2 = f"hysteria2://{ENV['UUID']}@{ip}:{ENV['HY2_PORT']}/?sni=www.bing.com&alpn=h3&insecure=1#{ENV['NAME']}-{isp}"
        subscription_lines.append(hysteria2)

    if ENV['TUIC_PORT'] != '40000':
        tuic = f"tuic://{ENV['UUID']}:admin@{ip}:{ENV['TUIC_PORT']}?sni=www.bing.com&alpn=h3&congestion_control=bbr#{ENV['NAME']}-{isp}"
        subscription_lines.append(tuic)

    if ENV['REALITY_PORT'] != '60000':
        reality = f"vless://{ENV['UUID']}@{ip}:{ENV['REALITY_PORT']}?encryption=none&flow=xtls - rprx - vision&security=reality&sni=who.cx&fp=chrome&pbk=&type=tcp&headerType=none#{ENV['NAME']}-{isp}"
        subscription_lines.append(reality)

    if subscription_lines:
        with open('list.txt', 'w') as f:
            f.write('\n'.join(subscription_lines) + '\n')

        with open('list.txt', 'rb') as f:
            content = f.read()
        with open(f"{ENV['FILE_PATH']}/sub.txt", 'wb') as f:
            f.write(base64.b64encode(content))

        console.print(f"[bold green]{ENV['FILE_PATH']}/sub.txt saved successfully[/bold green]")

        with open(f"{ENV['FILE_PATH']}/sub.txt", 'r') as f:
            sub_content = f.read()
        console.print(sub_content)

        send_telegram()


def main():
    os.makedirs(ENV['FILE_PATH'], exist_ok = True)
    for f in ['config.json', f"{ENV['FILE_PATH']}/sub.txt"]:
        if os.path.exists(f):
            os.remove(f)

    generate_cert()
    file_map = download_files()
    generate_config(file_map)
    run_services(file_map)

    ip, isp = get_ip_and_isp()
    generate_subscription(ip, isp)

    cleanup_files = ['config.json', 'list.txt']
    for f in cleanup_files:
        if os.path.exists(f):
            os.remove(f)

    os.system('cls' if os.name == 'nt' else 'clear')

    # 启动http服务
    port = int(ENV['PORT'])
    server = HTTPServer(('', port), RequestHandler)
    console.print(f"\n[bold green]Started HTTP server is running on port {port}[/bold green]")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == '__main__':
    main()


