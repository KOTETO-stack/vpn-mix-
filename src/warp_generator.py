#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import os
import secrets
from typing import Dict, List
from config import WARP_ENDPOINT, WARP_PUBLIC_KEY, WARP_IPV4, WARP_IPV6_PREFIX
import logging

logger = logging.getLogger('warp')

class WarpGenerator:
    def __init__(self):
        self.endpoint = WARP_ENDPOINT
        self.pubkey = WARP_PUBLIC_KEY
        
    def _gen_keys(self) -> Dict[str, str]:
        try:
            import subprocess
            priv = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, check=True).stdout.strip()
            pub = subprocess.run(['wg', 'pubkey'], input=priv, capture_output=True, text=True, check=True).stdout.strip()
            return {'private_key': priv, 'public_key': pub}
        except:
            priv = base64.b64encode(os.urandom(32)).decode()
            pub = base64.b64encode(os.urandom(32)).decode()
            return {'private_key': priv, 'public_key': pub}
            
    def generate(self) -> Dict:
        keys = self._gen_keys()
        ipv6 = f"{WARP_IPV6_PREFIX}{':'.join(f'{secrets.randbelow(65536):04x}' for _ in range(4))}"
        conf = f"""[Interface]
PrivateKey = {keys['private_key']}
Address = {WARP_IPV4}/32
Address = {ipv6}/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280

[Peer]
PublicKey = {self.pubkey}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {self.endpoint}
PersistentKeepalive = 25"""
        return {
            'config': {
                'interface': {'addresses': {'v4': WARP_IPV4, 'v6': ipv6}, 'private_key': keys['private_key']},
                'peers': [{'public_key': self.pubkey, 'endpoint': {'host': self.endpoint}}]
            },
            'wireguard_conf': conf
        }
        
    def get_configs(self, count: int = 3) -> List[Dict]:
        return [self.generate() for _ in range(count)]
