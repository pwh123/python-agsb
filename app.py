import os
import json
import subprocess
import base64
import time
import requests
import random
import string
import OpenSSL
import re
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from rich.console import Console

console = Console()

# 配置环境变量
ENV = {
    'UUID': os.getenv('UUID', '55e8ca56-8a0a-4486-b3f9-b9b0d46638a9'),  # 默认UUID
    'NEZHA_SERVER': os.getenv('NEZHA_SERVER', ''),             # 哪吒面板地址
    'NEZHA_PORT': os.getenv('NEZHA_PORT', ''),                      # 哪吒agent端口，为{443,8443,2096,2087,2083,2053}时自动开启tls
    'NEZHA_KEY': os.getenv('NEZHA_KEY', ''),                            # 哪吒密钥
    'ARGO_DOMAIN': os.getenv('ARGO_DOMAIN', ''),                        # 固定隧道Argo域名，留空即使用临时隧道
    'ARGO_AUTH': os.getenv('ARGO_AUTH', ''),                            # 固定argo隧道密钥，token或json，留空即使用临时隧道
    'CFIP': os.getenv('CFIP', '104.16.0.0'),                       # 优选域名或优选ip
    'CFPORT': os.getenv('CFPORT', '8443'),                              # 优选域名或优选ip对应端口
    'NAME': os.getenv('NAME', 'stim'),                                   # 节点名称
    'FILE_PATH': os.getenv('FILE_PATH', './.cache'),                    # 节点文件路径
    'ARGO_PORT': os.getenv('ARGO_PORT', '8001'),                        # ARGO端口,使用固定隧道token时,cloudflared 后台设置和需这里一致
    'TUIC_PORT': os.getenv('TUIC_PORT', '28045'),                       # TUIC端口,支持多端口的容器或玩具可以填写，否则不动
    'HY2_PORT': os.getenv('HY2_PORT', '28046'),                         # HY2端口，支持多端口的容器或玩具可以填写，否则不动
    'REALITY_PORT': os.getenv('REALITY_PORT', '60000'),                 # REALITY端口，支持多端口的容器或玩具可以填写，否则不动
    'PORT': os.getenv('PORT', '7860'),                                  # HTTP订阅端口，支持多端口可以订阅的可以填写开启订阅，否则不动
    'TELEGRAM_BOT_TOKEN': os.getenv('TELEGRAM_BOT_TOKEN', ''),          # Telegram Bot Token
    'TELEGRAM_CHAT_ID': os.getenv('TELEGRAM_CHAT_ID', ''),              # Telegram Chat ID
}

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'Hello World')
            
        elif self.path == '/sub':
            try:
                with open(f"{ENV['FILE_PATH']}/sub.txt", 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(content)
            except:
                self.send_response(404)
                self.end_headers()             

def send_telegram():
    """发送 Telegram 消息"""
    TELEGRAM_BOT_TOKEN = ENV['TELEGRAM_BOT_TOKEN']
    TELEGRAM_CHAT_ID = ENV['TELEGRAM_CHAT_ID']
    FILE_PATH = Path(ENV['FILE_PATH'])
    NAME = ENV.get('NAME', 'Node')  # 获取NAME，如果不存在则默认为'Node'

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        console.print("\n[bold magenta]Telegram bot token or chat ID is empty. Skip pushing nodes to TG[/bold magenta]")
        return

    try:
        with open(FILE_PATH / 'sub.txt', 'r', encoding='utf-8') as file:
            message = file.read().strip()

        # 处理特殊字符
        escaped_name = NAME
        for char in '_*[]()~`>#+=|{}.!-':
            escaped_name = escaped_name.replace(char, f'\\{char}')

        # 构建Markdown格式的消息
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
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    
    with open("cert.pem", "wb") as f:
        f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
    with open("private.key", "wb") as f:
        f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

def download_files():
    arch = os.uname().machine
    if arch in ['arm', 'arm64', 'aarch64']:
        files = {
            'web': 'https://arm64.ssss.nyc.mn/sb',
            'bot': 'https://arm64.ssss.nyc.mn/bot',
            'npm': 'https://arm64.ssss.nyc.mn/agent'
        }
    else:
        files = {
            'web': 'https://amd64.ssss.nyc.mn/sb',
            'bot': 'https://amd64.ssss.nyc.mn/2go',
            'npm': 'https://amd64.ssss.nyc.mn/agent'
        }
    
    file_map = {}
    for name, url in files.items():
        random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            with open(random_name, 'wb') as f:
                f.write(response.content)
            os.chmod(random_name, 0o755)
            file_map[name] = random_name
            console.print(f"[bold green]Downloaded {random_name} successfully[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Failed to download {random_name}: {str(e)}[/bold red]")
    
    return file_map

def generate_reality_keypair(web_file):
    cmd = f'./{web_file} generate reality-keypair'
    output = subprocess.check_output(cmd, shell=True).decode()
    private_key = ''
    public_key = ''
    for line in output.splitlines():
        if 'PrivateKey:' in line:
            private_key = line.split()[1]
        elif 'PublicKey:' in line:
            public_key = line.split()[1]
    return private_key, public_key

def generate_config(file_map):
    private_key, public_key = generate_reality_keypair(file_map['web'])
    
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
                "tag": "vless-ws-in",
                "type": "vless",
                "listen": "::",
                "listen_port": int(ENV['ARGO_PORT']),
                "users": [
                    {
                        "uuid": ENV['UUID']
                    }
                ],
                "transport": {
                    "type": "ws",
                    "path": "/vless",
                    "early_data_header_name": "Sec-WebSocket-Protocol"
                }
            },
            {
                "tag": "tuic-in",
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
                "tag": "hysteria2-in",
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
                "tag": "vless-reality-vesion",
                "type": "vless",
                "listen": "::",
                "listen_port": int(ENV['REALITY_PORT']),
                "users": [
                    {
                        "uuid": ENV['UUID'],
                        "flow": "xtls-rprx-vision"
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
                        "private_key": private_key,
                        "short_id": [""]
                    }
                }
            }
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "direct", "tag": "direct-ipv4-prefer-out", "domain_strategy": "prefer_ipv4"},
            {"type": "direct", "tag": "direct-ipv4-only-out", "domain_strategy": "ipv4_only"},
            {"type": "direct", "tag": "direct-ipv6-prefer-out", "domain_strategy": "prefer_ipv6"},
            {"type": "direct", "tag": "direct-ipv6-only-out", "domain_strategy": "ipv6_only"},
            {
                "type": "wireguard",
                "tag": "wireguard-out",
                "server": "engage.cloudflareclient.com",
                "server_port": 2408,
