#!/usr/bin/env python
# coding=utf-8

import socket
import urlparse


class ApacheProxyConnect(object):
    '''
    this class aim to detect the apache proxy enable function
    code from avws decode script: apache_proxy_connect_enable.script
    '''
    def __init__(self, url):
        self.url = self.normal_url(url)
        self.parsed_url = urlparse.urlparse(self.url)
        self.msg = {'vuln_name': 'apache proxy connect',
                'url': self.url,
                'proof': 'www.acunetix.wvs:443',
                'severity': 'medium'}

    def normal_url(self, url):
        if not url.startswith('http:') and not url.startswith('https:'):
            url = 'http://' + url

        return url

    def verify(self):
        payload = "GET " + '/' + "@" + 'www.acunetix.wvs' + ":" + '443' +  "/" + '/' + " HTTP/1.1\r\n"

        # get port
        if ':' in self.parsed_url.netloc:
            netloc, port = self.parsed_url.netloc.split(':')
        else:
            port = '80'
            netloc = self.parsed_url.netloc

        payload +=  "Host: " + netloc + "\r\n\r\n"

        # socket connect
        remoteserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remoteserver.settimeout(10)

        try:
            remoteserver.connect((netloc, int(port)))
            remoteserver.send(get)
            response = remoteserver.recv(4096)
        except:
            response = ''
        finally:
            remoteserver.close()

        if response.find('The proxy server could not handle the request <em><a href="www.acunetix.wvs:443">') > -1:
            return self.msg
        else:
            return None



def verify(ip, port=80, name='', timeout=10, types='ip'):
    if types == 'ip':
        url = "{}:{}".format(ip, port)
    else:
        url = ip
    result = ApacheProxyConnect(url).verify()
    return result


