#!/usr/bin/env python
# coding=utf-8

import requests
import urlparse
from config import *

def verify(ip, port=80, name='http', timeout=10, types='ip'):
    if 'http' not in name.lower():
        return

    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip


    if not url.startswith('http:/') or not url.startswith('https:/'):
        url = 'http://' + url

    parsed_url = urlparse.urlparse(url)
    target = parsed_url.scheme + "://" + parsed_url.netloc + "/bugscan.txt"
    try:
        req = requests.put(target, '202cb962ac59075b964b07152d234b70')
        req = requests.get(target)
        if req.status_code == 200 and '202cb962ac59075b964b07152d234b70' in req.content:
            info = {
                'url': target,
                'proof': target,
                'severity': 'high',
                'vuln_name': 'put file'
            }
            return info
    except Exception as e:
        pass
    
    return None
    