#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import base64
import json
import re
import urllib.parse
from typing import List, Dict
import aiohttp
import yaml
from config import FREE_SOURCES, LOG_LEVEL
import logging

logging.basicConfig(level=getattr(logging, LOG_LEVEL), format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('fetcher')

PATTERNS = {
    'vless': re.compile(r'vless://[^\s]+', re.I),
    'vmess': re.compile(r'vmess://[^\s]+', re.I),
    'trojan': re.compile(r'trojan://[^\s]+', re.I),
    'hysteria2': re.compile(r'hysteria2://[^\s]+', re.I),
    'hy2': re.compile(r'hy2://[^\s]+', re.I),
    'shadowsocks': re.compile(r'ss://[^\s]+', re.I),
}

class ConfigFetcher:
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=100, ssl=False),
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        return self
        
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
            
    async def fetch_url(self, url: str) -> str:
        try:
            async with self.session.get(url, allow_redirects=True) as r:
                if r.status == 200:
                    return await r.text()
        except Exception as e:
            logger.debug(f'Fetch error {url[:50]}: {e}')
        return ''
        
    def decode_b64(self, content: str) -> str:
        for pad in ['', '=', '==', '===']:
            try:
                decoded = base64.b64decode(content + pad).decode('utf-8', errors='ignore')
                if '://' in decoded:
                    return decoded
            except:
                pass
        return content
        
    def extract(self, text: str) -> Dict[str, List[str]]:
        configs = {'vless': [], 'vmess': [], 'trojan': [], 'hysteria2': [], 'shadowsocks': []}
        decoded = self.decode_b64(text)
        for proto, pat in PATTERNS.items():
            key = 'hysteria2' if proto in ['hysteria2', 'hy2'] else ('shadowsocks' if proto == 'shadowsocks' else proto)
            for m in pat.findall(decoded):
                m = m.strip()
                if m and m not in configs[key]:
                    configs[key].append(m)
        return configs
        
    def parse_clash(self, content: str) -> Dict[str, List[str]]:
        configs = {'vless': [], 'vmess': [], 'trojan': [], 'hysteria2': [], 'shadowsocks': []}
        try:
            data = yaml.safe_load(content)
            if not data or 'proxies' not in data:
                return configs
            for p in data['proxies']:
                t = p.get('type', '').lower()
                if t == 'vless':
                    configs['vless'].append(self._vless_uri(p))
                elif t == 'vmess':
                    configs['vmess'].append(self._vmess_uri(p))
                elif t == 'trojan':
                    configs['trojan'].append(self._trojan_uri(p))
                elif t in ['hysteria', 'hysteria2']:
                    configs['hysteria2'].append(self._hy2_uri(p))
                elif t in ['ss', 'shadowsocks']:
                    configs['shadowsocks'].append(self._ss_uri(p))
        except Exception as e:
            logger.debug(f'Clash parse error: {e}')
        return configs
        
    def _vless_uri(self, p: dict) -> str:
        try:
            params = {'security': 'tls' if p.get('tls') else 'none', 'sni': p.get('servername', ''), 'fp': p.get('client-fingerprint', 'chrome'), 'type': p.get('network', 'tcp')}
            if p.get('flow'):
                params['flow'] = p['flow']
            if p.get('reality-opts'):
                params['security'] = 'reality'
                params['pbk'] = p['reality-opts'].get('public-key', '')
                params['sid'] = p['reality-opts'].get('short-id', '')
            q = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            uri = f"vless://{p.get('uuid', '')}@{p.get('server', '')}:{p.get('port', '')}"
            if q:
                uri += '?' + q
            return uri + f"#{urllib.parse.quote(p.get('name', 'VLESS'))}"
        except:
            return ''
            
    def _vmess_uri(self, p: dict) -> str:
        try:
            cfg = {'v': '2', 'ps': p.get('name', 'VMess'), 'add': p.get('server', ''), 'port': str(p.get('port', '')), 'id': p.get('uuid', ''), 'aid': '0', 'scy': 'auto', 'net': p.get('network', 'tcp'), 'tls': 'tls' if p.get('tls') else ''}
            return f"vmess://{base64.b64encode(json.dumps(cfg).encode()).decode()}"
        except:
            return ''
            
    def _trojan_uri(self, p: dict) -> str:
        try:
            params = {'security': 'tls', 'sni': p.get('sni', ''), 'type': p.get('network', 'tcp'), 'fp': p.get('client-fingerprint', 'chrome')}
            q = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            uri = f"trojan://{p.get('password', '')}@{p.get('server', '')}:{p.get('port', '')}"
            if q:
                uri += '?' + q
            return uri + f"#{urllib.parse.quote(p.get('name', 'Trojan'))}"
        except:
            return ''
            
    def _hy2_uri(self, p: dict) -> str:
        try:
            params = {'sni': p.get('sni', ''), 'insecure': '1' if p.get('skip-cert-verify') else '0'}
            q = urllib.parse.urlencode({k: v for k, v in params.items() if v})
            uri = f"hysteria2://{p.get('password', '')}@{p.get('server', '')}:{p.get('port', '')}"
            if q:
                uri += '?' + q
            return uri + f"#{urllib.parse.quote(p.get('name', 'HY2'))}"
        except:
            return ''
            
    def _ss_uri(self, p: dict) -> str:
        try:
            ui = base64.b64encode(f"{p.get('cipher', '')}:{p.get('password', '')}".encode()).decode()
            return f"ss://{ui}@{p.get('server', '')}:{p.get('port', '')}#{urllib.parse.quote(p.get('name', 'SS'))}"
        except:
            return ''
            
    async def fetch_all(self) -> Dict[str, List[str]]:
        all_cfg = {'vless': [], 'vmess': [], 'trojan': [], 'hysteria2': [], 'shadowsocks': []}
        urls = set()
        for u in FREE_SOURCES.values():
            urls.update(u)
            
        results = await asyncio.gather(*[self.fetch_url(u) for u in urls], return_exceptions=True)
        
        for url, content in zip(urls, results):
            if not content or isinstance(content, Exception):
                continue
            if 'proxies:' in content:
                parsed = self.parse_clash(content)
            else:
                parsed = self.extract(content)
            for k, v in parsed.items():
                all_cfg[k].extend(v)
                
        for proto in all_cfg:
            seen = set()
            unique = []
            for c in all_cfg[proto]:
                if c and c not in seen:
                    seen.add(c)
                    unique.append(c)
            all_cfg[proto] = unique
            
        logger.info(f"Fetched {sum(len(v) for v in all_cfg.values())} configs")
        return all_cfg
