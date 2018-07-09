#!/usr/bin/env python
#coding=utf-8



import requests

def verify(ip, port=80, name=None, timeout=15):
    proxy = {'http': 'http://{}:{}'.format(ip, port), 
            'http': 'https://{}:{}'.format(ip, port)}

    info = {
        "url": '',
        "vuln_name": 'proxy detect',
        "severity": "high",
        "proof": 'curl -x {}:{} -v http://www.baidu.com'.format(ip, port)
    }
    try:
        headers= {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
                'Connection': 'close'}
        resp = requests.get('http://www.baidu.com', proxies=proxy, allow_redirects=False, timeout=timeout)
        if resp.status_code == 200 and 'www.baidu.com' in resp.text:
            info['url'] = 'http://{}:{}'.format(ip, port)
            return info
    except:
        pass