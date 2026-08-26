#!/usr/bin/env python3
# -*- coding: utf-8 -*-

FREE_SOURCES = {
    'vless': [
        'https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt',
        'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt',
        'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt',
        'https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt',
        'https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt',
        'https://raw.githubusercontent.com/free18/v2ray/main/v.txt',
        'https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs.txt',
        'https://raw.githubusercontent.com/itsyebekhe/PSG/main/lite/subscriptions/meta/mix',
        'https://raw.githubusercontent.com/itsyebekhe/PSG/main/lite/subscriptions/meta/reality',
        'https://sub.irys.dpdns.org/auto',
        'https://proxypool.link/clash/proxies',
        'https://shadowmere.xyz/api/b64sub',
    ],
    'vmess': [
        'https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vm.txt',
        'https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt',
    ],
    'trojan': [
        'https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/tr.txt',
        'https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt',
    ],
    'hysteria2': [
        'https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/hy2.txt',
        'https://raw.githubusercontent.com/mshojaei77/v2rayAuto/main/subs/hy2',
    ],
    'shadowsocks': [
        'https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/ss.txt',
        'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt',
    ],
    'clash': [
        'https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml',
        'https://raw.githubusercontent.com/NiREvil/vless/main/sub/clash-meta.yml',
    ],
}

BLOCKED_COUNTRIES = {'UA'}

OUTPUT_DIR = 'output'
MAX_SERVERS = 150
PING_TIMEOUT = 3
MIN_TLS_VERSION = '1.2'

WARP_ENDPOINT = 'engage.cloudflareclient.com:2408'
WARP_PUBLIC_KEY = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo='
WARP_IPV4 = '172.16.0.2'
WARP_IPV6_PREFIX = '2606:4700:110:'

AMNEZIA_FREE_KEY = 'vpn://AAAA_3icXY3LDoIwEEV_hXStJhhjojsjERN0AbowbkgtAzZA2_QBQcO_2xbduJrMPXfmvBHDLaBtgHYtgxfFwUECoFmAClBEUqEpZ_84IJwxIB7Zpt1KWuUdSDWVlzbEguYTsMEbKZAdJZDrQXgbnt7Ny6_tx4XkmhPe-E5fOWQss68M03Kws_D30qDRWYx-5gXW2Eucs4bB8Yg2qyTM-sUjO16u9SmKUxOt92VI6js_dzyNsz7cqOSGxvEDmaFXJg=='

LOG_LEVEL = 'INFO'
