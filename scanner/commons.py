#!/usr/bin/env python
# coding=utf-8
# import gevent
# from gevent import monkey
# monkey.patch_all()
# from gevent.queue import Queue as gQueue
import re
import threading
import nmap
import subprocess
import gevent
import hashlib
import socket
import json
import os
import requests
import time
import glob
import sys
import logging
import urlparse
import importlib
import urllib2
from bs4 import BeautifulSoup as bs
from Queue import Queue
from dummy import *
from scanner.models import *
from cgi import escape
from config import *

reload(sys)
sys.setdefaultencoding('utf-8')

socket.setdefaulttimeout(20)
here = os.path.split(os.path.abspath(__file__))[0]
requests.packages.urllib3.disable_warnings()

def parse_file(lines):
    """
    this function aim to parse the file which contains subdomain and the ips

    :param: lines, line contains www.iqiyi.com   129.0.0.1,127.213.21.32,
    :rtype: list,list,  uniq url list and uniq ip list
    """
    pattern_subDomains = re.compile(r"(\S+)[\s+|\t](.*)")
    # pattern_layer = re.compile(r"(\S+)\t(\S+).*")

    url_list = set()
    ip_list = set()
    # with open(filename, "r") as f:
    for line in lines:
        mat = pattern_subDomains.match(line)
        if mat:
            # print mat.groups()[1]
            url_list.add(mat.groups()[0])
            for _ in mat.groups()[1].split(","):
                ip_list.add(_.strip())
        else:
            raise Exception
                # logging.info(Fore.RED + "NOT MATCH THE PATTEN. MAY BE SHOULD CHOOSE ANOTHER PATTERN")
    return list(url_list), list(ip_list)

def is_internet(ip):
    """
    judge if the ip belongs to intranet
    :ip : format xxx.xxx.xx.xx

    : return: True/False
    """
    # todo: judge if match the format
    ip = ip.split(".")
    ip = [int(_) for _ in ip]
    # print ip
    if (ip[0]) == 10:
        return False
    elif (ip[0]) == 172 and (ip[1]) in range(16,32):
        return False
    elif (ip[0]) == 192 and (ip[1]) == 168:
        return False
    elif ip[0] == 127:
        return False
    else:
        return True


def is_ip(ip):
    ip = ip.split(".")
    if len(ip) != 4:
        return False
    ip = filter(lambda x: int(x) > 0 and int(x) < 255, ip)
    if len(ip) != 4:
        return False
    return True


def get_ip_target(iplist, num=15):
    """
    this function aim to get ip CIDR target through ip list
    :param: iplist, a list object contains ips
    :param: num, the nums we use most
    :rtype: list, a list obejcts contains nums's IP CIDR
    """
    net = {}

    for line in iplist:
        line = line.strip()
        # logging.info(Fore.RED + line + Style.RESET_ALL)
        if (not is_ip(line)) or (not is_internet(line)):
            continue
        else:
            tmp = line[:line.rindex(".")]
            if tmp in net:
                net[tmp] += 1
            else:
                net[tmp] = 1

    net = sorted(net.items(), lambda x,y:cmp(x[1], y[1]), reverse=True)
    # print net, len(net)
    # 如果大于10， 取前10， 如果小于10， 取全部
    if len(net) > num:
        result = net[:num]
    else:
        result = net

    suffix = ".1/24"
    ip_section = []
    for _ in result:
        ip_section.append(_[0] + suffix)
    return ip_section


# define a function which make threading work
def masscan_scan(scanqueue, resultqueue):
    """
    this function aim to scan in multithreading env
    so the parameter is a Queue objects

    :param: scanqueue,  the queue contains commands to scan
    :param: resultqueue, the queue which contains the xml infomations
    # :rtype: resultqueue, which is contains result of scan
    """

    # resultqueue = Queue()
    while not scanqueue.empty():
        try:
            command = scanqueue.get(timeout=0.5)
            s = subprocess.check_output(command, shell=True)
            if DEBUG:
                logger.info("[masscan_scan] run scan=[{}] successful".format(command))
            resultqueue.put(s)
        except Exception as e:
            logger.error("[masscan_scan] reason={}".format(repr(e)))


def masscan_work(command):
    """
    this is masscan work function, which is multithreading
    :param: scanqueue,  the queue contains command to scan
    :param: resultqueue, the queue will contains the scan result
    """

    try:
        s = subprocess.check_output(command, shell=True)
        if DEBUG:
            logger.info("[masscan_scan] run scan=[{}] successful".format(command))
    except Exception as e:
        try:
            s = subprocess.check_output("echo 'hello1.0' | sudo -S " + command, shell=True)
        except Exception as e:
            logger.error("[masscan_scan] reason={}".format(repr(e)))
            s = ""
    finally:
        return s


def parse_masscan_xml(content):
    """
    this function aim to parse the xml result from masscan_scan
    and return the format (ip, port, name, banner)
    :param: content,  the xml result get from masscan_scan
    :rtype: list,  contains the format (ip, port, name, banner)
    """
    result = {}
    soup = bs(content, "lxml")
    hosts = soup.find_all("host")
    for host in hosts:
        addr = host.find("address")["addr"]
        # print addr["addr"]
        port = host.find("port")
        # print port
        state = port.find("state")["reason"]
        if state == "response":
            name = port.find("service")["name"]
            banner = port.find("service")["banner"]
        else:
            name = ""
            banner = ""
        if (addr, port["portid"]) in result:
            name1, banner1 = result[(addr, port["portid"])]
            if name1 in ["title", ""]:
                result[(addr, port["portid"])] = (name, banner.split("\\x0a")[0])

        else:
            result[(addr, port["portid"])] = (name, banner.split("\\x0a")[0])
        if DEBUG:
            logger.info("[parse_masscan_xml] info=[{}]".format((addr, port["portid"], name, banner.split("\\x0a")[0])))
    items = result.items()
    tmp = [(item[0][0], item[0][1], item[1][0], item[1][1]) for item in items]
    return tmp



def save_masscan_result_to_porttable(content, id_domain):
    """
    this function aim to save the masscan result to database,
    masscan result like [(ip, port, name, banner),]
    :param: content,  the masscan result
    :type: None
    """
    for x in content:
        ip, port, name, banner = x
        try:

            port_obj, created = PortTable.objects.get_or_create(
                ip=ip,
                port=int(port),
                # name=name,
                # product=banner,
                id_domain=id_domain,
            )
            port_obj.name = name
            port_obj.product = banner
            port_obj.save()
            if DEBUG:
                if created:
                    logger.info("[save_masscan_result_to_porttable] create port_table obj= {}".format(port_obj))
        except Exception as e:
            logger.error("[save_masscan_result_to_porttable] reason={}".format(repr(e)))




#def nmapscan(ipportqueue, resultqueue, id_domain, arguments=None):
def nmapscan(ipportqueue, id_domain, arguments=None):
    """
    this aim to use nmap to scan the host and port to get the infomation of the
    host and it's port
    :ipportqueue: the queue contains(ip, port, name, version)
    :arguments: the arguments of nmap scan
    :rtype: list [(host;hostname;hostname_type;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe),()]
    """
    # if port is None:
    #     port = TARGET_PORTS
    if arguments is None:
        arguments = "-sV"
    # nmap_result = []
    nm = nmap.PortScanner()
    while not ipportqueue.empty():
        try:
            host,port = ipportqueue.get()
            #print "[host={}] [port={}]".format(host, port)
            nm.scan(host, str(port), arguments=arguments)
            #print "[nm.csv()={}]".format(nm.csv())
            csv = nm.csv()
            for scan_result in csv.split("\r\n")[1:]:
                scan_result = scan_result.split(";")
                logger.info("[common] [nmap_scan] scan_result: {}".format(scan_result))
                if (not len(scan_result)== 13) or (scan_result[6] != "open"):
                    PortTable.objects.filter(ip=host).filter(port=port).filter(id_domain=id_domain).delete()
                    #continue
                else:
                    ip = scan_result[0]
                    port = scan_result[4]
                    protocol = scan_result[3]
                    name = scan_result[5]
                    product = scan_result[7]
                    extrainfo = scan_result[8]
                    version = scan_result[10]
                    conf = scan_result[11] + "|**|" + scan_result[12]
                    save_nmap_result_to_database(ip, port, protocol, name, product, extrainfo, version, conf, id_domain)
                # resultqueue.put(tuple(scan_result))
        except Exception as e:
            logger.error("[common] [nmap_scan] Error: {}".format(repr(e)))
        # logger.info("[common] [nmap_scan] scan_result: {}".format(nmap_result))

#def nmap_work(ipportlist, resultqueue, id_domain):
def nmap_work(ipportlist, id_domain):
    """
    this is nmap work function, which is multithreading
    :param: scanqueue,  the queue contains command to scan
    :param: resultqueue, the queue will contains the scan result
    :param: id_domain,  the domain id number
    """
    ipportqueue = Queue()
    for i in ipportlist:
        ipportqueue.put(i)

    threads = []
    for i in xrange(6):
        thd = threading.Thread(target=nmapscan, args=(ipportqueue, id_domain))
        threads.append(thd)
    for thd in threads:
        thd.start()

    for thd in threads:
        thd.join()


def save_nmap_result_to_database(ip,
                                port,
                                protocol,
                                name,
                                product,
                                extrainfo,
                                version,
                                conf,
                                id_domain):
    try:
        obj = PortTable.objects.filter(ip=ip).filter(port=port).filter(id_domain=id_domain)[0]
        if obj:
            obj.protocol = protocol
            obj.name = name
            obj.product = product
            obj.extrainfo = extrainfo
            obj.version = version
            obj.conf = conf
        else:
            obj = PortTable(ip=ip,
                    port=port,
                    protocol=protocol,
                    name=name,
                    # product=product,
                    extrainfo=extrainfo,
                    version=version,
                    conf=conf,
                    id_domain=id_domain)
            if product:
                obj.product = product
        obj.save()
    except Exception as e:
        logger.error("[commons] [save_nmap_result_to_database] [error={}]".format(repr(e)))


def fetch_title(portobjlist, threadnum=10):
    """
    this function aim to fetch the http title
    :param: portobjlist = [(ip, port, id_domain)]
    """
    BLACK_PORTS = set(["23", "25", "53", "873", "27017", "1935", "2181", "22", "995", "445", "465", "139", "1099", "1090", "3306", "5432", "3389", "6379", "1433", "11211"])
    objqueue = Queue()
    for obj in portobjlist:
        if str(obj[2]) not in BLACK_PORTS:
            objqueue.put(obj)

    threads = []
    for i in xrange(threadnum):
        t = threading.Thread(target=fetch_title_work, args=(objqueue,))
        threads.append(t)
    for t in threads:
        t.start()

    for t in threads:
        t.join()





def decode_response_text(text):
    for _ in ['UTF-8', 'GB2312', 'GBK', 'iso-8859-1', 'big5']:
        try:
            result = text.encode(_)
            return result
        except Exception as e:
            pass
    # if cannot encode the title . return it.
    return text




def http_request(url, result, compress=False):
    raw_headers = {"User-Agent" : "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
                    "Connection": "close"}

    range_headers = {"User-Agent" : "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0",
        'Range': 'bytes=0-1024',
        "Connection": "close"}

    if compress:
        headers = range_headers
    else:
        headers = raw_headers

    try:
        html = requests.get(url,
                headers=headers,
                allow_redirects=True,
                timeout=10,
                verify=False)

        status = html.status_code
        headers = html.headers
        # html = decode_response_text(html.text)
        html = (html.text)

    except Exception as e:
        # print "[http_reqeusts] [error reason={}]".format(repr(e))
        html = ""
        status = -1
        headers = {}
    finally:
        result.append(html)
        result.append(status)
        result.append(headers)
        return result

def is_http(ip, port):
    """
    this function aim to detect if the service running in the port is
    http service
    """
    service = None
    try:
        a = socket.create_connection((ip, int(port)), timeout=10)
        a.send('GET / HTTP/1.1\r\n\r\n')
        data = a .recv(30)
        a.close()
        if 'HTTP' in data:
            service = 'http'
    except Exception as e:
        pass
    return service

def fetch_title_work(objqueue):
    """
    the multithread work to fetch http title
    :param: objqueue Queue((ip, port, id_domain))
    """
    while not objqueue.empty():
        try:
            obj = objqueue.get()
            portobjid, ip, port = obj
            if int(port) not in [80,81, 443] or  (int(port) > 9000 and int(port) < 7000):
                if is_http(ip, port) != 'http':
                    continue
            scheme = "http" if str(port) not in ["443", "8443"] else "https"
            url = scheme + "://" + ip + ":" + str(port)
            print "[fetch_title_work] [url={}]".format(url)
            tmp = []
            html = http_request(url, tmp)
            html = html[0]
            """


            start_time = time.time()
            t = threading.Thread(target=http_request, args=(url, html))
            t.daemon = True
            t.start()
            while t.isAlive():
                if ((time.time() - start_time) > 15):
                    raise Exception("http request take more than 15s")
                else:
                    time.sleep(1.0)

            if not html:
                raise Exception("http request return nothing")
            else:
                html = html[0]
            """
            title =  re.findall("<title>(.*)</title>", html, re.I)
            if title:
                title = title[0]
                """
                try:
                    title = title[0].decode("utf-8", ignore=True)
                except:
                    title = title[0]
                """
            else:
                title = html.replace("\n", "").replace('\r', '').strip()[:200]
            # update 18-01-08 save the obj to database
            title = decode_response_text(title)
            title = escape(title)
            print "[title={}]".format(title)
            update_httptitle_to_database(portobjid, title)

        except Exception as e:
            logger.error("[fetch_title_work] [reason={}]".format(repr(e)))


def update_httptitle_to_database(portobjid, title):
    """
    this will update the port_table with the http title and
    :param portobjid: is the id of a item in port_table
    :param title: is the title to update
    """

    try:
        portobj = PortTable.objects.get(id=portobjid)
        portobj.httptitle = title
        portobj.save()
    except Exception as e:
        logger.error("[update_httptitle_to_database] [reason={}]".format(repr(e)))


class PocPlugin(object):
    def __init__(self, urlqueue):
        super(PocPlugin, self).__init__()
        self.urlqueue = urlqueue
        self.scanfuncs = []
        self.verifyfuncs = []
        self.loadscript()
        logger.info("verifyfuncs has {} script and bugscan has {} scripts".format(len(self.verifyfuncs), len(self.scanfuncs)))

    def loadscript(self):
        """
        this function load the script from util/script/poc*.py
        and return the list
        """
        # print "[loadscript] [inhere...] [{}]".format(os.path.realpath(__file__))
        # print os.system("pwd")
        pyfiles = glob.glob("scanner/util/script/poc*.py")
        pyfiles = [i[:-3] for i in pyfiles]
        pyfiles = [i.replace("/", ".") for i in pyfiles]
        # print pyfiles
        scriptslist = [importlib.import_module(i) for i in pyfiles]
        # print scripts
        self.bugscanplugin = (s for s in scriptslist if hasattr(s, "audit") and hasattr(s, 'assign'))
        tmp = (s for s in scriptslist if hasattr(s, "verify"))
        for t in tmp:
            self.verifyfuncs.append(getattr(t, "verify"))

        for plugin in self.bugscanplugin:
            try:
                assign = getattr(plugin, "assign")
                audit = getattr(plugin, "audit")
                self.scanfuncs.append((assign, audit))
            except Exception as e:
                logger.info("getattr function occure a error")
        #print "total {} script, total {} verify".format(len(scripts), sum(functions))

    def _scanwork(self):
        while not self.urlqueue.empty():
            obj = self.urlqueue.get(timeout=4)
            for funcs in self.scanfuncs:
                assign = funcs[0]
                audit = funcs[1]
                if obj.cmstype:
                    # if obj.cmstype is True, means it's a http service
                    cmstype = json.loads(obj.cmstype)
                    _u = 'http://{}:{}'.format(obj.ip, obj.port)
                    for cms in cmstype:
                        cms = cms.encode('utf-8')
                        res = assign(cms, _u)
                        if res and len(res) == 2 and res[0]:
                            result = audit(res[1])
                            if result:
                                pass
                else:
                    # if obj.cmstype is None， means it's not http service
                    if obj.name:
                        # if nmap recognize the service name, pass
                        res = assign(obj.name, obj.ip)
                        if res and len(res) == 2 and res[0]:
                            result = audit(res[1])
                            if result:
                                pass
                    else:
                        # if not recognize the service name, pass ip
                        res = assign('ip', obj.ip)
                        if res and len(res) == 2 and res[0]:
                            result = audit(res[1])
                            if  result:
                                pass

            for vfunc in self.verifyfuncs:
                _r = vfunc(obj.ip, obj.port, obj.name)
                if _r:
                    pass



    def scan(self, threadnum=10):
        threads = []
        for t in xrange(threadnum):
            _x = threading.Thread(target=self._scanwork)
            threads.append(_x)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def pocscan(urlqueue):
    p = PocPlugin(urlqueue)
    p.scan()




"""
def decode_response_text(txt, charset=None):
    if charset:
        try:
            return txt.decode(charset)
        except:
            pass

    for _ in ['UTF-8', 'GB2312', 'GBK', 'iso-8859-1', 'big5']:
        try:
            return txt.decode(_)
        except:
            pass

    try:
        return txt.decode('ascii', 'ignore')
    except:
        pass

    #raise Exception('Fail to decode response Text')
    return txt

"""

class InfoLeakScan():
    """
    InfoLeakScan aim to scan the sensitive folder or sensitive file
    it's result saved the found target.
    """
    error_flag = re.compile(r'Error|Error Page|Unauthorized|Welcome to tengine!|Welcome to OpenResty!|invalid service url|Not Found|不存在|未找到|410 Gone|looks like something went wrong|Bad Request|Welcome to nginx!', re.I)

    def __init__(self, url):
        self.scheme, self.netloc, self.path = self.parse_url(url)
        self.url = self.scheme + "://" + self.netloc + "/"
        self.checkset = self.load_files("./scanner/util/info.txt", self.url)
        self.result = Queue()
        self.has401 = False
        self.lenth_404_page = self.get_404()
        self.access_length_set = set()
        self.lock = threading.Lock()


    def parse_url(self, url):
        """
        parse url and return it's scheme, netloc, path
        """
        if not url.find("://") > 0:
            url = "http://" + url
        if url.find('443') > 0:
            url = url.replace('http://', 'https://')
        _ = urlparse.urlparse(url)
        return _.scheme, _.netloc, _.path if _.path else "/"


    def get_request(self, url, compress=False):
        ret = []
        try:
            ret = http_request(url, ret)
            """
            start_time = time.time()
            t = threading.Thread(target=http_request, args=(url, ret, compress))
            t.daemon = True
            t.start()
            while t.isAlive():
                if time.time() - start_time > 15:
                    print "[get_request] [time > 15s]"
                    return (-1, {}, "")
                else:
                    time.sleep(1.0)
            if not ret:
                return (-1, {}, "")
            """
            html = ret[0]
            status = ret[1]
            headers = ret[2]
            return (status, headers, html)
        except Exception as e:
            logger.error("[InfoLeak] [get_reqeust] [reason={}]".format(repr(e)))
            return (-1, {}, "")

    def get_404(self):
        """
        get 404 page, check status_code, black item, and len of html_doc
        """
        errorpage = self.url + "Check-404-exists-page-test"
        status, headers, html_doc = self.get_request(errorpage)
        lenth_404_page = len(html_doc)

        return  lenth_404_page

    def check_exist(self, url, lenth_404_page, compress=False):
        status, headers, html_doc = self.get_request(url, compress=compress)
        #print "[url={}] [status={}]".format(url, status)
        exist = False
        # chekc if in  [301, 302, 400, 404, 501, 502, 503, 505]
        if status in [-1, 301, 302, 400, 403, 404, 500, 501, 502, 503, 505]:
            return exist

        """
        if status == 401:
            exist = True
            return exist
        """

        is_404 = False
        # if status is 404,
        if status == 404:
            is_404 = True
        elif len(html_doc) < 20:
            is_404 = True
        elif InfoLeakScan.error_flag.findall(html_doc):
            is_404 = True
        else:
            _len = len(html_doc)
            _min = min(_len, lenth_404_page)
            if _min == 0:
                _min = 10.0
            if abs(float(_len - lenth_404_page)) / _min < 0.3:
                is_404 = True

        if compress and status == 200:
            is_404 = True
        # if is_404
        if is_404:
            return exist


        if status == 206:
            if (headers.get("Content-Type", "").find("text") > -1) \
                or (headers.get("Content-Type", "").find("html") > -1):
                pass
            else:
                exist = True
        else:
            if status == 200 and \
               ((headers.get("Content-Type", "").find("text") > 0)
                or (headers.get("Content-Type", "").find("html") > 0)
                or (headers.get("Content-Type", "").find("json") > 0)):
                exist = True

        if exist and status == 401:
            if self.has401:
                exist = False
            else:
                self.has401 = True
                exist = True

        if exist:
            x = len(html_doc) - len(url)
            if len(html_doc) in self.access_length_set or x in self.access_length_set:
                exist = False
            else:
                self.access_length_set.add(len(html_doc))
                self.access_length_set.add(x)
        return exist

    def load_files(self, filename, url):
        # based on payload, judge if need the last /
        if url.endswith("/"):
            url = url.rstrip("/")

        files = Queue()
        with open(filename, "r") as f:
            for line in f.xreadlines():
                if line.startswith("#"):
                    continue
                line = line.strip()
                line = url + line
                files.put(line)

        return files

    def is_compress(self, url):
        scheme, netloc, path = self.parse_url(url)
        COMPRESS_FILE = ['zip', '7z', 'tar.gz', 'tar', 'rar', 'tar.bz2', 'bz2', 'log', "out", "tgz", "gz"]
        for i in COMPRESS_FILE:
            if i in path:
                return True

        return False

    def _scan_work(self):
        """
        this is the single thread scan work
        """
        while not self.checkset.empty():
            try:
                url = self.checkset.get()
            except Exception:
                return
            # print url
            if self.is_compress(url):
                exist = self.check_exist(url, self.lenth_404_page, compress=True)
            else:
                exist = self.check_exist(url, self.lenth_404_page)

            if exist:
                self.result.put(url)

    def scan(self, threads=10):
        try:
            all_threads = []
            for i in xrange(threads):
                t = threading.Thread(target=self._scan_work)
                t.start()
                all_threads.append(t)

            for thread in all_threads:
                thread.join()
        except Exception as e:
            logger.error("[infoscan] [scan] [reason={}]".format(repr(e)))



class InfoLeakScanGevent():
    """
    InfoLeakScan aim to scan the sensitive folder or sensitive file
    it's result saved the found target.
    """
    error_flag = re.compile(r'Error|Error Page|Unauthorized|Welcome to tengine!|Welcome to OpenResty!|invalid service url|Not Found|不存在|未找到|410 Gone|looks like something went wrong|Bad Request|Welcome to nginx!', re.I)

    def __init__(self, url):
        self.scheme, self.netloc, self.path = self.parse_url(url)
        self.url = self.scheme + "://" + self.netloc + "/"
        self.checkset = self.load_files("/home/shinpachi/tool/scanner/webscanner/scanner/util/info.txt", self.url)
        self.result = gQueue()
        self.has401 = False
        self.lenth_404_page = self.get_404()
        self.access_length_set = set()
        self.lock = threading.Lock()


    def parse_url(self, url):
        """
        parse url and return it's scheme, netloc, path
        """
        if not url.find("://") > 0:
            url = "http://" + url
        if url.find('443') > 0:
            url = url.replace('http://', 'https://')
        _ = urlparse.urlparse(url)
        return _.scheme, _.netloc, _.path if _.path else "/"


    def get_request(self, url, compress=False):
        ret = []
        try:
            ret = http_request(url, ret)
            """
            start_time = time.time()
            t = threading.Thread(target=http_request, args=(url, ret, compress))
            t.daemon = True
            t.start()
            while t.isAlive():
                if time.time() - start_time > 15:
                    print "[get_request] [time > 15s]"
                    return (-1, {}, "")
                else:
                    time.sleep(1.0)
            if not ret:
                return (-1, {}, "")
            """
            html = ret[0]
            status = ret[1]
            headers = ret[2]
            return (status, headers, html)
        except Exception as e:
            logging.error("[InfoLeak] [get_reqeust] [reason={}]".format(repr(e)))
            return (-1, {}, "")

    def get_404(self):
        """
        get 404 page, check status_code, black item, and len of html_doc
        """
        errorpage = self.url + "Check-404-exists-page-test"
        status, headers, html_doc = self.get_request(errorpage)
        lenth_404_page = len(html_doc)

        return  lenth_404_page

    def check_exist(self, url, lenth_404_page, compress=False):
        status, headers, html_doc = self.get_request(url, compress=compress)
        #print "[url={}] [status={}]".format(url, status)
        exist = False
        # chekc if in  [301, 302, 400, 404, 501, 502, 503, 505]
        if status in [-1, 301, 302, 400, 403, 404, 500, 501, 502, 503, 505]:
            return exist

        """
        if status == 401:
            exist = True
            return exist
        """

        is_404 = False
        # if status is 404,
        if status == 404:
            is_404 = True
        elif len(html_doc) < 20:
            is_404 = True
        elif InfoLeakScan.error_flag.findall(html_doc):
            is_404 = True
        else:
            _len = len(html_doc)
            _min = min(_len, lenth_404_page)
            if _min == 0:
                _min = 10.0
            if abs(float(_len - lenth_404_page)) / _min < 0.3:
                is_404 = True

        if compress and status == 200:
            is_404 = True
        # if is_404
        if is_404:
            return exist


        if status == 206:
            if (headers.get("Content-Type", "").find("text") > -1) \
                or (headers.get("Content-Type", "").find("html") > -1):
                pass
            else:
                exist = True
        else:
            if status == 200 and \
               ((headers.get("Content-Type", "").find("text") > 0)
                or (headers.get("Content-Type", "").find("html") > 0)
                or (headers.get("Content-Type", "").find("json") > 0)):
                exist = True

        if exist and status == 401:
            if self.has401:
                exist = False
            else:
                self.has401 = True
                exist = True

        if exist:
            x = len(html_doc) - len(url)
            if len(html_doc) in self.access_length_set or x in self.access_length_set:
                exist = False
            else:
                self.access_length_set.add(len(html_doc))
                self.access_length_set.add(x)
        return exist

    def load_files(self, filename, url):
        # based on payload, judge if need the last /
        if url.endswith("/"):
            url = url.rstrip("/")

        files = gQueue()
        with open(filename, "r") as f:
            for line in f.xreadlines():
                if line.startswith("#"):
                    continue
                line = line.strip()
                line = url + line
                files.put(line)

        return files

    def is_compress(self, url):
        scheme, netloc, path = self.parse_url(url)
        COMPRESS_FILE = ['zip', '7z', 'tar.gz', 'tar', 'rar', 'tar.bz2', 'bz2', 'log', "out", "tgz", "gz"]
        for i in COMPRESS_FILE:
            if i in path:
                return True

        return False

    def _scan_work(self):
        """
        this is the single thread scan work
        """
        while not self.checkset.empty():
            try:
                url = self.checkset.get()
            except Exception:
                return
            # print url
            if self.is_compress(url):
                exist = self.check_exist(url, self.lenth_404_page, compress=True)
            else:
                exist = self.check_exist(url, self.lenth_404_page)

            if exist:
                self.result.put(url)

    def scan(self, threadnum=40):
        try:
            threads = [gevent.spawn(self._scan_work) for i in xrange(threadnum)]
            gevent.joinall(threads)
        except Exception as e:
            logging.error("[infoscan] [scan] [reason={}]".format(repr(e)))









def save_vuln_to_db(id_domain, url, vuln_name, **param):
    """
        url = models.TextField(blank=True, null=True)
        parameters = models.TextField(blank=True, null=True)
        headers_string = models.TextField(blank=True, null=True)
        method = models.CharField(max_length=15, blank=True, null=True)
        delta_time = models.CharField(max_length=50, blank=True, null=True)
        vuln_name = models.CharField(max_length=150, blank=True, null=True)
        severity = models.CharField(max_length=30, blank=True, null=True)
        checks = models.CharField(max_length=150, blank=True, null=True)
        proof = models.TextField(blank=True, null=True)
        seed = models.TextField(blank=True, null=True)
        id_domain = models.IntegerField(blank=True, null=True)
    """
    try:
        obj = Vulns(
            id_domain = id_domain,
            url = url,
            vuln_name = vuln_name,
            headers_string = param["headers_string"] if "headers_string" in param else "",
            method = param["method"] if "method" in param else "",
            delta_time = param["delta_time"] if "delta_time" in param else "",
            severity = param["severity"] if "severity" in param else "",
            checks = param["checks"] if "checks" in param else "",
            proof = param["proof"] if "proof" in param else "",
            seed = param["seed"] if "seed" in param else "",

        )
        obj.save()
    except Exception as e:
        logger.error("[save_vuln_to_db] [reason={}]".format(repr(e)))




def format_url(url):
    try:
        s = url.find('://')
        if s < 0:
            url = "http://" + url
        if url.count('/') == 2:
            url += '/'
        if url.find('443') > 0:
            url = url.replace('http://', 'https://')
        return url
    except Exception as e:
        logger.error('[format_url] Exception %s' % str(e))
        return None



class Condition(object):
    def __init__(self, feature=None):
        self.feature = None
        self.url = None
        self.cms_name = None
        self.separate_chars = '||||'
        self.parsed_list = []
        self.parse(feature)

    def get_url(self):
        return self.url

    def _parse_inner(self, con):
        try:
            fmt = {
                "header": [],
                "body": [],
                "title": []
            }
            t_list = con.split('&&')
            for t in t_list:
                t = t.strip('() ')
                s = t.find('=')
                if s < 0:
                    logger.error('[_parse_inner] Error format %s' % t)
                    continue
                k = str(t[:s].strip()).lower()
                v = t[s + 1:].strip('" ()').replace('\\', '')
                if k.endswith('!'):
                    prefix = '^'
                    k = k[0:k.find('!')]
                else:
                    prefix = ''
                if k == 'header' or k == 'body' or k == 'title':
                    fmt[k].append(prefix + v)
                else:
                    logger.error('[_parse_inner] unknown key %s in %s' % (k, con))
            return fmt
        except Exception as e:
            logger.error('[_parse_inner] Exception %s when parsing %s' % (e, con))

    def parse(self, feature):
        try:
            if not feature:
                return
            self.feature = feature.strip()
            p = self.feature.split(self.separate_chars)
            if not p or len(p) < 3:
                logger.error('Fail to parse feature: %s' % feature)
                return
            self.cms_name = p[1]
            if len(p) == 3:
                self.url = '/'
                feature = p[2]
            else:
                self.url = p[2]
                feature = p[3]
            if not feature:
                logger.error('Condition is empty: %s' % self.feature)
                return
            c_list = feature.split('||')
            for c in c_list:
                c = c.strip("() ")
                if not c:
                    continue
                r = self._parse_inner(c)
                if r:
                    self.parsed_list.append(r)
            return True
        except Exception as e:
            logger.error('Exception %s when parsing %s' % (e, self.feature))


class KeyItem(object):
    def __init__(self, url):
        self.url = url
        self.condition_list = []


class ConditionSet(object):
    def __init__(self):
        self.key_item_list = []

    def find_item(self, url, auto_add=True):
        for t in self.key_item_list:
            if t.url == url:
                return t
        if auto_add:
            return self.add_item(url)

    def add_item(self, url):
        _t = KeyItem(url)
        self.key_item_list.append(_t)
        return _t

    def add_condition(self, con):
        t = self.find_item(con.url)
        if t:
            t.condition_list.append(con)


class CMSRecognize2(object):
    def __init__(self):
        self.is_web = False
        self.match_detail = None
        self.condition_set = ConditionSet()
        self.init_dict = False

    def _load_dict(self):
        dic_path = "%s/util/cms_data.list" % here

        count = 0
        #dic_path = "%s/util/cms_data.list" % here
        fd = open(dic_path)
        for line in fd:
            line = line.strip(" \r\n")
            if not line or line.startswith('#'):
                continue
            p = Condition()
            if p.parse(line):
                self.condition_set.add_condition(p)
                count += 1
            else:
                logger.error('[CMSRecognize2] Fail to load %s' % line)
        fd.close()
        logger.info("%s features loaded." % count)

    def _contain_keywords(self, content, keyword_list):
        if not content or not keyword_list:
            return
        if not isinstance(keyword_list, tuple) and not isinstance(keyword_list, list):
            keyword_list = [keyword_list]
        for k in keyword_list:
            if k.startswith('^'):
                k = k[1:]
                if content.find(k) >= 0:
                    return False
            elif content.find(k) < 0:
                return False
        return True

    def _parse_cms(self, code, header, body, _key_item, cms_list):
        for con in _key_item.condition_list:
            if cms_list.count(con.cms_name) > 0:
                continue
            for p in con.parsed_list:
                if self._contain_keywords(header, p['header']) or self._contain_keywords(body, p['body']) or \
                        self._contain_keywords(body, p['title']):
                    if cms_list.count(con.cms_name) == 0:
                        cms_list.append(con.cms_name)
                    break

        return cms_list

    def recognize_cms(self, web_host):
        try:
            if not self.init_dict:
                self.init_dict = True
                self._load_dict()

            count = 0
            err_count = 0
            is_web = False
            normal_url = format_url(web_host)
            if normal_url is None:
                return None
            cms_name = []
            #print "the length of self.condition_set is {}".format(len(self.condition_set.key_item_list))
            for _key_item in self.condition_set.key_item_list:
                req_url = normal_url.rstrip("/") + _key_item.url
                logger.info("[CMSRecognize2] [recognize_cms] [req_url= {}   ]".format(req_url))
                code, header, body, err, _ = hackhttp.http(req_url)
                if code >= 100:
                    is_web = True
                if code <= 0 or err != 0:
                    err_count += 1
                if err_count >= 2 and not is_web:
                    return
                if code != 200:
                    continue
                self._parse_cms(code, header, body, _key_item, cms_name)
            if is_web:
                cms_name.append('www')
            return cms_name if cms_name else None
        except Exception as e:
            logger.error('%s when recognize %s' % (e, web_host))



class CMSGuessThread(threading.Thread):
    def __init__(self, urlqueue):
        threading.Thread.__init__(self)
        self.urlqueue = urlqueue
        self.p = CMSRecognize2()

    def guess_cms(self):
        while True:
            if self.urlqueue.empty():
                break
            url, objid, isip = self.urlqueue.get(timeout=2)
            cmstype = self.p.recognize_cms(url)
            logger.info( "[CMSGuessThread] [guess_cms] [cmstype={}]".format(cmstype))
            if cmstype:
                cmstype = json.dumps(cmstype)
                update_cmstype_to_database(cmstype, objid, isip)

    def run(self):
        self.guess_cms()




def update_cmstype_to_database(cmstype, objid, isip=False):
    """
    this function aim to save the cmstype to table
    :cmstype: the type get from cms_guess
    :objid: the id to belong a obj
    :isip: if True, aim to PortTable obj, else aim to Subdomains obj
    """
    if isip:
        portobj = PortTable.objects.get(id=objid)
        portobj.cmstype = cmstype
        portobj.save()
    else:
        subdomainobj = Subdomains.objects.get(id=objid)
        subdomainobj.cmstype = cmstype
        subdomainobj.save()


def cms_guess(urlqueue, threadnum=10):
    """
    this function aim to detect the cms type of one web site
    :param: urlqueue  which contains (url, objid, isip)
    :param: threadnum, the thread number to exec
    :rtype: None
    """
    threads = []
    for t in xrange(threadnum):
        _x = CMSGuessThread(urlqueue)
        threads.append(_x)

    for t in threads:
        t.start()

    for t in threads:
        t.join()




if __name__ == '__main__':
    # task_masscan("127.0.0.1/26")
    # a = Queue()
    # b = Queue()
    # a.put(("106.38.219.44", "80", "", ""))
    # a.put(("106.38.219.58", "80", "", ""))
    # a.put(("106.38.219.79", "873", "", ""))
    # a.put(("106.38.219.59", "443", "", ""))
    # a.put(("36.110.220.170", "8080", "", ""))
    # nmap_work(a, b)
    # while not b.empty():
    #     print b.get()
    a = InfoLeakScan("http://211.151.158.132")
    a.scan()
    while not a.result.empty():
        print a.result.get()
