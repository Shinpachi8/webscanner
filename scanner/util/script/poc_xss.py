# coding=utf-8
import urllib2
import re
import urllib
import requests
import urlparse
import HTMLParser
from config import *


def get_url(domain, timeout):
    url_list = []
    try:
        res = urllib2.urlopen('http://' + domain, timeout=timeout)
    except Exception as e:
        return []
    html = res.read()
    root_url = res.geturl()
    m = re.findall("<a[^>]*?href=('|\")(.*?)\\1", html, re.I)
    if m:
        for url in m:
            ParseResult = urlparse.urlparse(url[1])
            if ParseResult.netloc and ParseResult.scheme:
                if domain == ParseResult.hostname:
                    url_list.append(HTMLParser.HTMLParser().unescape(url[1]))
            elif not ParseResult.netloc and not ParseResult.scheme:
                url_list.append(HTMLParser.HTMLParser().unescape(urlparse.urljoin(root_url, url[1])))
    return list(set(url_list))



def verify(ip, port=80, name='', timeout=10, types='ip'):
    if 'http' not in name.lower():
        return

    if types == 'ip':
        url = ip + ':' + str(port)
    else:
        url = ip

    # if not url.startswith('http:/') or not url.startswith('https:/'):
    #     url = 'http://' + url

    urllist = get_url(url, 10)
    for url in urllist:
        parsed_url = urlparse.urlparse(url)
        if not parsed_url.query:
            continue

        xss_payloads = getPayload(parsed_url.query, 'xss')

        for payload in xss_payloads:
            query = urllib.urlencode(payload)
            target = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, query, parsed_url.fragment))
            try:
                resp = requests.get(target, verify=False, timeout=10)
                if resp.status_code != 200:
                    break
                html = resp.text
                for p in XSS_PAYLOAD:
                    if p in html:
                        info = {
                            'url': target,
                            'severity': 'low',
                            'proof': p,
                            'vuln_name': 'xss'
                        }
                        return info
            except Exception as e:
                continue