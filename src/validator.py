#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import ipaddress
import re
import socket
import time
from typing import List, Dict, Optional, Tuple
import aiohttp
from dataclasses import dataclass, asdict
from config import BLOCKED_COUNTRIES, PING_TIMEOUT, MIN_TLS_VERSION
import logging

logger = logging.getLogger('validator')

@dataclass
class ServerInfo:
    protocol: str
    uri: str
    host: str
    port: int
    country: str = ''
    latency_ms: float = -1.0
    alive: bool = False
    secure: bool = False
    tags: List[str] = None
    error: str = ''
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
            
    def to_dict(self):
        return asdict(self)

class ConfigValidator:
    def __init__(self, max_concurrent=50):
        self.sem = asyncio.Semaphore(max_concurrent)
        self.ccache = {}
        self.dcache = {}
        
    def parse_uri(self, uri: str) -> Optional[Tuple[str, str, int]]:
        try:
            proto, rest = uri.split('://', 1)
            proto = proto.lower()
            if '@' in rest:
                _, hp = rest.split('@', 1)
            else:
                hp = rest
            if '#' in hp:
                hp = hp.split('#')[0]
            if '?' in hp:
                hp = hp.split('?')[0]
            if ':' in hp:
                if hp.startswith('['):
                    m = re.match(r'\[(.+?)\]:(\d+)$', hp)
                    if m:
                        return proto, m.group(1), int(m.group(2))
                else:
                    parts = hp.rsplit(':', 1)
                    return proto, parts[0], int(parts[1])
            return proto, hp, 443
        except:
            return None
            
    async def resolve(self, host: str) -> Optional[str]:
        if host in self.dcache:
            return self.dcache[host]
        try:
            ipaddress.ip_address(host)
            self.dcache[host] = host
            return host
        except ValueError:
            pass
        try:
            loop = asyncio.get_event_loop()
            info = await loop.getaddrinfo(host, None, family=socket.AF_INET)
            if info:
                ip = info[0][4][0]
                self.dcache[host] = ip
                return ip
        except:
            return None
            
    async def get_country(self, ip: str) -> str:
        if ip in self.ccache:
            return self.ccache[ip]
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(f'http://ip-api.com/json/{ip}?fields=countryCode,status', timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status == 200:
                        d = await r.json()
                        if d.get('status') == 'success':
                            self.ccache[ip] = d.get('countryCode', 'XX')
                            return self.ccache[ip]
        except:
            pass
        self.ccache[ip] = 'XX'
        return 'XX'
        
    async def ping(self, host: str, port: int) -> Tuple[bool, float]:
        try:
            t0 = time.time()
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=PING_TIMEOUT)
            lat = (time.time() - t0) * 1000
            w.close()
            await w.wait_closed()
            return True, lat
        except:
            return False, -1.0
            
    async def check_tls(self, host: str, port: int) -> bool:
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            loop = asyncio.get_event_loop()
            def _check():
                with socket.create_connection((host, port), timeout=PING_TIMEOUT) as s:
                    with ctx.wrap_socket(s, server_hostname=host) as ss:
                        return ss.version() >= MIN_TLS_VERSION
            return await loop.run_in_executor(None, _check)
        except:
            return False
            
    async def validate(self, uri: str, protocol: str) -> ServerInfo:
        async with self.sem:
            parsed = self.parse_uri(uri)
            if not parsed:
                return ServerInfo(protocol=protocol, uri=uri, host='err', port=0, error='parse')
            proto, host, port = parsed
            
            ip = await self.resolve(host)
            if not ip:
                return ServerInfo(protocol=protocol, uri=uri, host=host, port=port, error='dns')
                
            cc = await self.get_country(ip)
            if cc in BLOCKED_COUNTRIES:
                return ServerInfo(protocol=protocol, uri=uri, host=host, port=port, country=cc, error='blocked')
                
            alive, lat = await self.ping(ip, port)
            if not alive:
                return ServerInfo(protocol=protocol, uri=uri, host=host, port=port, country=cc, alive=False, error='timeout')
                
            secure = False
            if port == 443 or protocol in ['vless', 'vmess', 'trojan', 'hysteria2']:
                secure = await self.check_tls(ip, port)
                
            tags = []
            if secure:
                tags.append('secure')
            if lat < 100:
                tags.append('fast')
            if protocol == 'vless' and 'reality' in uri.lower():
                tags.append('reality')
            if protocol == 'hysteria2':
                tags.append('quic')
                
            return ServerInfo(protocol=protocol, uri=uri, host=host, port=port, country=cc, latency_ms=round(lat, 1), alive=True, secure=secure, tags=tags)
            
    async def validate_all(self, configs: Dict[str, List[str]]) -> List[ServerInfo]:
        tasks = []
        for proto, uris in configs.items():
            for uri in uris:
                tasks.append(self.validate(uri, proto))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid = []
        for r in results:
            if isinstance(r, Exception):
                continue
            if not r.error:
                valid.append(r)
                
        logger.info(f'Valid: {len(valid)}')
        return valid
        
    def sort(self, servers: List[ServerInfo]) -> List[ServerInfo]:
        return sorted(servers, key=lambda s: (s.alive, s.secure, -s.latency_ms if s.latency_ms > 0 else -9999), reverse=True)
