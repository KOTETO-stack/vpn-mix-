#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import urllib.parse
from typing import List, Dict, Optional
from validator import ServerInfo
from config import MAX_SERVERS
import logging

logger = logging.getLogger('converter')

class ConfigConverter:
    def to_v2ray(self, servers: List[ServerInfo]) -> str:
        valid = [s for s in servers if s.protocol in ['vless', 'vmess', 'trojan', 'hysteria2', 'shadowsocks']][:MAX_SERVERS]
        return base64.b64encode('\n'.join(s.uri for s in valid).encode()).decode()
        
    def to_clash(self, servers: List[ServerInfo], amnezia=None, warp=None) -> str:
        import yaml
        valid = [s for s in servers if s.protocol in ['vless', 'vmess', 'trojan', 'hysteria2', 'shadowsocks']][:MAX_SERVERS]
        
        proxies = []
        names = []
        for i, s in enumerate(valid):
            name = f"{s.country}-{s.protocol.upper()}-{i+1}"
            names.append(name)
            p = self._clash_proxy(s, name)
            if p:
                proxies.append(p)
                
        warp_names = []
        if warp:
            for i, w in enumerate(warp):
                wn = f'WARP-{i+1}'
                warp_names.append(wn)
                names.append(wn)
                wg = self._parse_wg(w.get('wireguard_conf', ''))
                proxies.append({
                    'name': wn, 'type': 'wireguard', 'server': 'engage.cloudflareclient.com',
                    'port': 2408, 'ip': '172.16.0.2', 'private-key': 'PLACEHOLDER',
                    'public-key': wg.get('PublicKey', ''), 'allowed-ips': ['0.0.0.0/0', '::/0'],
                    'udp': True, 'mtu': 1280
                })
                
        if amnezia:
            names.append('Amnezia-Free')
            proxies.append({
                'name': 'Amnezia-Free', 'type': 'wireguard', 'server': 'amnezia.server',
                'port': 51820, 'ip': '10.8.1.2', 'private-key': 'PLACEHOLDER',
                'public-key': 'PLACEHOLDER', 'allowed-ips': ['0.0.0.0/0', '::/0'],
                'udp': True, 'mtu': 1420
            })
            
        groups = [
            {'name': 'Auto-Select', 'type': 'url-test', 'url': 'http://www.gstatic.com/generate_204', 'interval': 300, 'tolerance': 50, 'proxies': names},
            {'name': 'Fallback', 'type': 'fallback', 'url': 'http://www.gstatic.com/generate_204', 'interval': 60, 'tolerance': 50, 'proxies': ['Auto-Select'] + warp_names + ['Amnezia-Free'] + ['DIRECT']},
            {'name': 'YouTube', 'type': 'select', 'proxies': ['Fallback', 'Auto-Select'] + names},
            {'name': 'Telegram', 'type': 'select', 'proxies': ['Fallback', 'Auto-Select'] + names},
            {'name': 'TikTok', 'type': 'select', 'proxies': ['Fallback', 'Auto-Select'] + names},
            {'name': 'Calls', 'type': 'select', 'proxies': ['Fallback', 'Auto-Select'] + warp_names + names},
            {'name': 'GLOBAL', 'type': 'select', 'proxies': ['Fallback', 'Auto-Select', 'DIRECT'] + names}
        ]
        
        rules = [
            'DOMAIN-SUFFIX,whatsapp.com,Calls',
            'DOMAIN-SUFFIX,whatsapp.net,Calls',
            'DOMAIN-SUFFIX,wa.me,Calls',
            'DOMAIN-SUFFIX,wechat.com,Calls',
            'DOMAIN-SUFFIX,weixin.qq.com,Calls',
            'DOMAIN-SUFFIX,bip.com,Calls',
            'DOMAIN-SUFFIX,bip.ru,Calls',
            'DOMAIN-SUFFIX,youtube.com,YouTube',
            'DOMAIN-SUFFIX,youtu.be,YouTube',
            'DOMAIN-KEYWORD,youtube,YouTube',
            'DOMAIN-SUFFIX,telegram.org,Telegram',
            'DOMAIN-SUFFIX,t.me,Telegram',
            'DOMAIN-SUFFIX,tiktok.com,TikTok',
            'DOMAIN-KEYWORD,tiktok,TikTok',
            'GEOSITE,category-ads-all,REJECT',
            'DOMAIN-SUFFIX,yandex.ru,DIRECT',
            'DOMAIN-SUFFIX,vk.com,DIRECT',
            'DOMAIN-SUFFIX,mail.ru,DIRECT',
            'GEOIP,RU,DIRECT',
            'MATCH,Fallback'
        ]
        
        return yaml.dump({
            'mixed-port': 7890, 'mode': 'rule', 'log-level': 'info',
            'dns': {'enable': True, 'enhanced-mode': 'fake-ip', 'nameserver': ['https://1.1.1.1/dns-query']},
            'proxies': proxies, 'proxy-groups': groups, 'rules': rules
        }, allow_unicode=True, sort_keys=False)
        
    def to_singbox(self, servers: List[ServerInfo], amnezia=None, warp=None) -> str:
        valid = [s for s in servers if s.protocol in ['vless', 'vmess', 'trojan', 'hysteria2', 'shadowsocks']][:MAX_SERVERS]
        outbounds = []
        tags = []
        
        for i, s in enumerate(valid):
            tag = f"{s.country}-{s.protocol.upper()}-{i+1}"
            tags.append(tag)
            o = self._singbox_outbound(s, tag)
            if o:
                outbounds.append(o)
                
        warp_tags = []
        if warp:
            for i, w in enumerate(warp):
                wt = f'WARP-{i+1}'
                warp_tags.append(wt)
                tags.append(wt)
                outbounds.append({
                    'type': 'wireguard', 'tag': wt, 'server': 'engage.cloudflareclient.com',
                    'server_port': 2408, 'local_address': ['172.16.0.2/32'],
                    'private_key': 'PLACEHOLDER', 'peer_public_key': w.get('config', {}).get('peers', [{}])[0].get('public_key', ''),
                    'mtu': 1280
                })
                
        if amnezia:
            tags.append('Amnezia-Free')
            outbounds.append({
                'type': 'wireguard', 'tag': 'Amnezia-Free', 'server': 'amnezia.server',
                'server_port': 51820, 'local_address': ['10.8.1.2/24'],
                'private_key': 'PLACEHOLDER', 'peer_public_key': 'PLACEHOLDER', 'mtu': 1420
            })
            
        fallback = ['Auto-Select'] + warp_tags + ['Amnezia-Free', 'direct']
        
        return json.dumps({
            'log': {'level': 'info'},
            'dns': {'servers': [{'tag': 'remote', 'address': 'https://1.1.1.1/dns-query'}], 'final': 'remote'},
            'inbounds': [
                {'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': 2080},
                {'type': 'tun', 'auto_route': True, 'strict_route': False}
            ],
            'outbounds': [
                {'tag': 'proxy', 'type': 'selector', 'outbounds': tags},
                {'tag': 'Auto-Select', 'type': 'url-test', 'outbounds': tags, 'url': 'http://www.gstatic.com/generate_204', 'interval': '5m'},
                {'tag': 'Fallback', 'type': 'fallback', 'outbounds': fallback, 'url': 'http://www.gstatic.com/generate_204', 'interval': '1m'},
                {'tag': 'direct', 'type': 'direct'},
                {'tag': 'block', 'type': 'block'},
                *outbounds
            ],
            'route': {
                'rules': [
                    {'domain_suffix': ['whatsapp.com', 'whatsapp.net', 'wa.me'], 'outbound': 'Fallback'},
                    {'domain_suffix': ['wechat.com', 'weixin.qq.com'], 'outbound': 'Fallback'},
                    {'domain_suffix': ['bip.com', 'bip.ru'], 'outbound': 'Fallback'},
                    {'domain_suffix': ['youtube.com', 'youtu.be'], 'outbound': 'Fallback'},
                    {'domain_suffix': ['telegram.org', 't.me'], 'outbound': 'Fallback'},
                    {'domain_suffix': ['tiktok.com'], 'outbound': 'Fallback'},
                    {'geosite': 'category-ads-all', 'outbound': 'block'},
                    {'geosite': 'category-ru', 'outbound': 'direct'},
                    {'ip_is_private': True, 'outbound': 'direct'}
                ],
                'final': 'Fallback', 'auto_detect_interface': True
            }
        }, indent=2, ensure_ascii=False)
        
    def _clash_proxy(self, s: ServerInfo, name: str) -> Optional[Dict]:
        parsed = urllib.parse.urlparse(s.uri)
        q = urllib.parse.parse_qs(parsed.query)
        if s.protocol == 'vless':
            return {
                'name': name, 'type': 'vless', 'server': s.host, 'port': s.port,
                'uuid': parsed.username or '', 'tls': q.get('security', [''])[0] in ['tls', 'reality'],
                'network': q.get('type', ['tcp'])[0], 'udp': True, 'client-fingerprint': 'chrome'
            }
        elif s.protocol == 'vmess':
            try:
                b64 = parsed.username or ''
                pad = 4 - len(b64) % 4
                if pad != 4:
                    b64 += '=' * pad
                cfg = json.loads(base64.b64decode(b64).decode())
                return {
                    'name': name, 'type': 'vmess', 'server': cfg.get('add', s.host),
                    'port': int(cfg.get('port', s.port)), 'uuid': cfg.get('id', ''),
                    'alterId': 0, 'cipher': 'auto', 'tls': cfg.get('tls') == 'tls',
                    'network': cfg.get('net', 'tcp'), 'udp': True
                }
            except:
                return None
        elif s.protocol == 'trojan':
            return {
                'name': name, 'type': 'trojan', 'server': s.host, 'port': s.port,
                'password': parsed.username or '', 'tls': True, 'udp': True
            }
        elif s.protocol == 'hysteria2':
            return {
                'name': name, 'type': 'hysteria2', 'server': s.host, 'port': s.port,
                'password': parsed.username or '', 'udp': True
            }
        elif s.protocol == 'shadowsocks':
            try:
                info = base64.b64decode(parsed.username + '==').decode().split(':', 1)
                return {
                    'name': name, 'type': 'ss', 'server': s.host, 'port': s.port,
                    'cipher': info[0], 'password': info[1], 'udp': True
                }
            except:
                return None
        return None
        
    def _singbox_outbound(self, s: ServerInfo, tag: str) -> Optional[Dict]:
        parsed = urllib.parse.urlparse(s.uri)
        q = urllib.parse.parse_qs(parsed.query)
        if s.protocol == 'vless':
            return {
                'type': 'vless', 'tag': tag, 'server': s.host, 'server_port': s.port,
                'uuid': parsed.username or '', 'flow': q.get('flow', [''])[0] or None,
                'tls': {'enabled': True, 'server_name': q.get('sni', [''])[0], 'utls': {'enabled': True, 'fingerprint': 'chrome'}} if q.get('security', [''])[0] in ['tls', 'reality'] else None
            }
        elif s.protocol == 'trojan':
            return {
                'type': 'trojan', 'tag': tag, 'server': s.host, 'server_port': s.port,
                'password': parsed.username or '',
                'tls': {'enabled': True, 'server_name': q.get('sni', [''])[0]}
            }
        elif s.protocol == 'hysteria2':
            return {
                'type': 'hysteria2', 'tag': tag, 'server': s.host, 'server_port': s.port,
                'password': parsed.username or '',
                'tls': {'enabled': True, 'server_name': q.get('sni', [''])[0]}
            }
        elif s.protocol == 'shadowsocks':
            try:
                info = base64.b64decode(parsed.username + '==').decode().split(':', 1)
                return {
                    'type': 'shadowsocks', 'tag': tag, 'server': s.host, 'server_port': s.port,
                    'method': info[0], 'password': info[1]
                }
            except:
                return None
        return None
        
    def _parse_wg(self, conf: str) -> Dict:
        result = {}
        for line in conf.split('\n'):
            line = line.strip()
            if '=' in line and not line.startswith('[') and not line.startswith('#'):
                k, v = line.split('=', 1)
                result[k.strip()] = v.strip()
        return result
