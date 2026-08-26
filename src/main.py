#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import json
import os
import sys
from datetime import datetime

from config import OUTPUT_DIR
from fetcher import ConfigFetcher
from validator import ConfigValidator
from converter import ConfigConverter
from warp_generator import WarpGenerator
from amnezia import AmneziaIntegration
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('main')

async def main():
    logger.info('=== Auto VPN Russia ===')
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    async with ConfigFetcher() as fetcher:
        raw = await fetcher.fetch_all()
    
    validator = ConfigValidator()
    servers = validator.sort(await validator.validate_all(raw))
    
    warp = WarpGenerator().get_configs(3)
    amnezia = AmneziaIntegration().get_configs()
    amnezia_wg = amnezia[0] if amnezia else None
    
    converter = ConfigConverter()
    
    with open(os.path.join(OUTPUT_DIR, 'v2ray-base64.txt'), 'w') as f:
        f.write(converter.to_v2ray(servers))
        
    with open(os.path.join(OUTPUT_DIR, 'clash.yaml'), 'w') as f:
        f.write(converter.to_clash(servers, amnezia_wg, warp))
        
    with open(os.path.join(OUTPUT_DIR, 'singbox.json'), 'w') as f:
        f.write(converter.to_singbox(servers, amnezia_wg, warp))
        
    for i, w in enumerate(warp):
        with open(os.path.join(OUTPUT_DIR, f'warp-wg-{i+1}.conf'), 'w') as f:
            f.write(w['wireguard_conf'])
            
    with open(os.path.join(OUTPUT_DIR, 'amnezia-free.key'), 'w') as f:
        f.write(AmneziaIntegration().export_key())
        
    stats = {
        'updated_at': datetime.utcnow().isoformat() + 'Z',
        'total': len(servers),
        'by_proto': {},
        'by_country': {}
    }
    for s in servers:
        stats['by_proto'][s.protocol] = stats['by_proto'].get(s.protocol, 0) + 1
        stats['by_country'][s.country] = stats['by_country'].get(s.country, 0) + 1
        
    with open(os.path.join(OUTPUT_DIR, 'stats.json'), 'w') as f:
        json.dump(stats, f, indent=2)
        
    logger.info(f'Done: {len(servers)} servers')
    return 0

if __name__ == '__main__':
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        logger.exception('Fatal')
        sys.exit(1)
