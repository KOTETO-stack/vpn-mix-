#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import zlib
from typing import Dict, List, Optional
from config import AMNEZIA_FREE_KEY
import logging

logger = logging.getLogger('amnezia')

class AmneziaIntegration:
    def __init__(self):
        self.key = AMNEZIA_FREE_KEY
        self.decoded = self._decode()
        
    def _decode(self) -> Optional[Dict]:
        try:
            data = self.key.replace('vpn://', '')
            pad = 4 - len(data) % 4
            if pad != 4:
                data += '=' * pad
            decoded = base64.urlsafe_b64decode(data)
            decompressed = zlib.decompress(decoded[4:])
            return json.loads(decompressed.decode())
        except Exception as e:
            logger.error(f'Decode error: {e}')
            return None
            
    def get_info(self) -> Dict:
        if not self.decoded:
            return {}
        return {
            'name': self.decoded.get('name', 'Amnezia Free'),
            'protocol': self.decoded.get('api_config', {}).get('service_protocol', 'awg'),
            'api_key': self.decoded.get('auth_data', {}).get('api_key', ''),
        }
        
    def get_configs(self) -> List[Dict]:
        info = self.get_info()
        if not info:
            return []
        return [{
            'name': info['name'],
            'protocol': info['protocol'],
            'api_key': info['api_key'],
            'key': self.key,
            'note': 'Import into AmneziaVPN app. Real WG params require app auth.'
        }]
        
    def export_key(self) -> str:
        return self.key
