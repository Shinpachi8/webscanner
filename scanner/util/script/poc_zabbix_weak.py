#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from config import *

def check(site, _dir, app, lang):
    if 'zabbix' in app.split(','):
        return True
    return False

def verify(ip, port=80, name='', timeout=10, types='ip'):
    if 'http' not in name.lower():
        return

    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip
    if not url.startswith('http:/') or not url.startswith('https:/'):
        url = 'http://' + url

    passwd = ['zabbix','123456','admin']
    for pwd in passwd:
        try:
            url = url + '/index.php'
            code, head, html = http_request_post(url, {'sid':'sid', 'enter':'Sign in', 'name':'admin', 'password':pwd}, allow_redirects=True)
            if 'charts.php' in html:
                details = 'Zabbix Weak admin / %s' % (pwd)
                # target = site + _dir
                info = {
                    'url': url,
                    'vuln_name': 'zabbix weak password',
                    'severity': 'high',
                    'proof': details
                }
                return info
        except Exception, e:
            pass
