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
import socket
import json
import os
import requests
import time
import glob
import sys
import logging
import urlparse
import httplib
import ssl
import importlib
import urllib2
import string
from multiprocessing import Process
import random
import pymysql
from os import system
from os import path
from bs4 import BeautifulSoup as bs
from Queue import Queue
from hashlib import md5
from util.BBScan_YuanHao.BBScan import InfoDisScanner, ArgsConfig
from dummy import *
from scanner.models import *
from cgi import escape
from config import *

reload(sys)
sys.setdefaultencoding('utf-8')

socket.setdefaulttimeout(20)
here = os.path.split(os.path.abspath(__file__))[0]
requests.packages.urllib3.disable_warnings()
logging.getLogger('requests').setLevel(logging.WARNING)


PORT1 = '3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100'
PORT2 = '1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366'
PORT3 = '2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449'
PORT4 = '4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6379-6380,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019'
PORT5 = '7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8000-8999,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11211-11212,11967,12000,12174,12265,12345,13456,13722,13782-13783'
PORT6 = '14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27017-27018,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389'

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


def get_md5(str):
    return md5(str).hexdigest()


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




#def nmapscan(ipportqueue, resultqueue, id_domain, arguments=None):
def nmap_scan_job(ipportqueue, id_domain, scanall=True, arguments=None):
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
        arguments = "-sV --script banner --open"
    # nmap_result = []
    nm = nmap.PortScanner()
    while not ipportqueue.empty():
        try:
            host, port = ipportqueue.get()
            # print "[host={}] [port={}]".format(host, port)
            if scanall:
                nm.scan(host, port, arguments=arguments)
            #print "[nm.csv()={}]".format(nm.csv())
            csv = nm.csv()
            for scan_result in csv.split("\r\n")[1:]:
                scan_result = scan_result.split(";")
                # logger.info("[common] [nmap_scan] scan_result: {}".format(scan_result))
                if (not len(scan_result)== 13):
                    continue
                elif (scan_result[5].find('tcpwrapped') > -1):
                    continue
                elif (scan_result[6] != "open"):
                    PortTable.objects.filter(ip=host).filter(port=port).filter(id_domain=id_domain).delete()
                    continue
                else:
                    ip = scan_result[0]
                    port = scan_result[4]
                    protocol = scan_result[3]
                    name = scan_result[5]
                    product = scan_result[7]
                    extrainfo = scan_result[8]
                    version = scan_result[10]
                    conf = scan_result[11] + "|**|" + scan_result[12]
                    print "nmap.scan.result==== {}:{}:{}".format(ip, port, name)
                    # if port in databases, then update, else insert
                    portobj = PortTable.objects.filter(ip=ip).filter(port=port).filter(id_domain=id_domain).exists()
                    if portobj:
                        PortTable.objects.filter(ip=ip).filter(port=port).filter(id_domain=id_domain).update(
                            name = pymysql.escape_string(name),
                            protocol = pymysql.escape_string(protocol),
                            product = pymysql.escape_string(product),
                            extrainfo = pymysql.escape_string(extrainfo),
                            version = pymysql.escape_string(version),
                            conf = pymysql.escape_string(conf),
                        )
                    else:
                        PortTable(
                            ip= ip,
                            port=port,
                            protocol=pymysql.escape_string(protocol),
                            name=pymysql.escape_string(name),
                            product=pymysql.escape_string(product),
                            extrainfo=pymysql.escape_string(extrainfo),
                            version=pymysql.escape_string(version),
                            conf=pymysql.escape_string(conf),
                            id_domain=id_domain
                        ).save()

                    # try:
                    #     s = MySQLUtils()
                    #     check_if_exist = 'select * from port_table where ip=\'{}\' and port=\'{}\' and id_domain={}'
                    #     data = s.fetchone(check_if_exist.format(ip, port, id_domain))
                    #     if data:
                    #         update_nmap_result = "update port_table set protocol='{}', name='{}', product='{}', extrainfo='{}', version='{}', conf='{}' where id={}"
                    #         s.insert(update_nmap_result.format(pymysql.escape_string(protocol), pymysql.escape_string(name), pymysql.escape_string(product), pymysql.escape_string(extrainfo), pymysql.escape_string(version), pymysql.escape_string(conf), data[0]))
                    #     else:
                    #         insert_nmap_result = "insert into port_table (ip, port, protocol, name, product, extrainfo, version, conf, id_domain) values ('{ip}', '{port}', '{protocol}', '{name}', '{product}', '{extrainfo}', '{version}', '{conf}', '{id_domain}')"
                    #         s.insert(insert_nmap_result.format(ip=pymysql.escape_string(ip),
                    #             port=port,
                    #             protocol=pymysql.escape_string(protocol),
                    #             name=pymysql.escape_string(name),
                    #             product=pymysql.escape_string(product),
                    #             extrainfo=pymysql.escape_string(extrainfo),
                    #             version=pymysql.escape_string(version),
                    #             conf=pymysql.escape_string(conf),
                    #             id_domain=id_domain))
                    # except Exception as e:
                    #     logger.error("insert/update nmap result error={}".format(repr(e)))
                    # finally:
                    #     s.close()
                    # save_nmap_result_to_database(ip, port, protocol, name, product, extrainfo, version, conf, id_domain)
                # resultqueue.put(tuple(scan_result))
        except Exception as e:
            logger.error("[common] [nmap_scan] Error: {}".format(repr(e)))
        # logger.info("[common] [nmap_scan] scan_result: {}".format(nmap_result))

#def nmap_work(ipportlist, resultqueue, id_domain):
def nmap_work(ip, id_domain, port=None, threadnum=6):
    """
    this is nmap work function, which is multithreading
    :param: scanqueue,  the queue contains command to scan
    :param: resultqueue, the queue will contains the scan result
    :param: id_domain,  the domain id number
    """
    ipportqueue = Queue()
    # for port in ['1-10000', '10001-20000', '20001-30000', '30001-40000', '40001-50000', '50001-65535']:
    if port is None:
        for p in [PORT1, PORT2, PORT3, PORT4, PORT5, PORT6]:
            ipportqueue.put((ip, p))
    else:
        # 每一个端口起一个进程来扫nmap，可能有点浪费，不过先这样吧，数量不多可以忍
        for item in ip:
            ipportqueue.put((item[0], item[1] ))

    threads = []
    for i in xrange(threadnum):
        thd = threading.Thread(target=nmap_scan_job, args=(ipportqueue, id_domain))
        threads.append(thd)
    for thd in threads:
        thd.start()

    for thd in threads:
        thd.join()




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
    for _ in ['utf-8', 'gb2312', 'gbk', 'iso-8859-1', 'big5']:
        try:
            result = text.decode(_).encode('UTF-8')
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


def fetch_title_work(objqueue):
    """
    the multithread work to fetch http title
    :param: objqueue Queue((ip, port, id_domain))
    """
    while not objqueue.empty():
        try:
            obj = objqueue.get()
            portobjid, ip, port = obj
            ishttp = True
            if is_https(ip, port) == 'https':
                ishttp = False
            elif is_http(ip, port) == 'http':
                ishttp = True
            else:
                continue
            scheme = "http" if ishttp  else "https"
            url = '{}://{}:{}'.format(scheme, ip, port)
            logger.info( "[fetch_title_work] [url={}]".format(url))
            tmp = []
            html = http_request(url, tmp)
            html = html[0]

            title =  re.findall("<title>(.*)?</title>", html, re.I)
            if title:
                title = title[0]
            else:
                title = html.replace("\n", "").replace('\r', '').replace(' ', '').strip()[:200]
            # update 18-01-08 save the obj to database
            title = decode_response_text(title)
            title = escape(title)
            print "[title={}]".format(title)
            PortTable.objects.filter(id=portobjid).update(httptitle=(title))
            # portobj.save()
            # update_httptitle_to_database = 'update port_table set httptitle=\'{}\' where id={}'
            # save2sql(update_httptitle_to_database.format(pymysql.escape_string(title), portobjid))

        except Exception as e:
            logger.error("[fetch_title_work] [reason={}]".format(repr(e)))





class PocPlugin(object):
    def __init__(self, urlqueue, types='ip', id_domain='1'):
        super(PocPlugin, self).__init__()
        self.urlqueue = urlqueue
        self.scanfuncs = []
        self.verifyfuncs = []
        self.types =types
        self.id_domain = id_domain
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
        scriptslist = [(i,importlib.import_module(i)) for i in pyfiles]
        # print scripts
        self.bugscanplugin = (s for s in scriptslist if hasattr(s[1], "audit") and hasattr(s[1], 'assign'))
        tmp = (s for s in scriptslist if hasattr(s[1], "verify"))
        for t in tmp:
            self.verifyfuncs.append((t[0], getattr(t[1], "verify")))

        for plugin in self.bugscanplugin:
            try:
                assign = getattr(plugin[1], "assign")
                audit = getattr(plugin[1], "audit")
                self.scanfuncs.append((plugin[0], assign, audit))
            except Exception as e:
                logger.info("getattr function occure a error")
        #print "total {} script, total {} verify".format(len(scripts), sum(functions))

    def _scanwork(self):
        while not self.urlqueue.empty():
            logger.info("remains-------{} task to scan".format(self.urlqueue.qsize()))
            obj = self.urlqueue.get(timeout=4)
            if len(obj) == 2:
                ip = obj[0]
                port = '80'
                name = 'http'
            else:
                ip = obj[0]
                port = obj[1]
                name = obj[2]
                cmstype = obj[3]
            insert_vuln_sql = 'insert into vulns (url, vuln_name, severity, proof, id_domain) values ("{url}", "{vuln_name}", "{severity}", "{proof}", "{id_domain}")'
            for funcs in self.scanfuncs:
                assign = funcs[1]
                audit = funcs[2]

                        # if nmap recognize the service name, pass
                logger.info("now load  bugscan script: {} and service == 'www', ip={}".format(funcs[0], ip))
                res = assign('www', ip)
                if res and len(res) == 2 and res[0]:
                    result = audit(res[1])
                    if result:
                        md5 = get_md5(result['url'] + '|' + result['vuln_name'])
                        if Vulns.objects.filter(md5=md5).exists():
                            pass
                        else:
                            Vulns(url=pymysql.escape_string(result['url']),
                                vuln_name=pymysql.escape_string(result['vuln_name']),
                                severity=result['severity'],
                                proof=pymysql.escape_string(result['proof']),
                                id_domain = self.id_domain,
                                md5=md5).save()

                logger.info("now done with bugscan script: {} and service == 'www', ip={}".format(funcs[0], ip))
                    # else:
                        # if not recognize the service name, pass ip
                logger.info("now load bugscan script: {} and service == 'ip', ip={}".format(funcs[0], ip))
                res = assign('ip', ip)
                if res and len(res) == 2 and res[0]:
                    result = audit(res[1])
                    if  result:
                        md5 = get_md5(result['url'] + '|' + result['vuln_name'])
                        if Vulns.objects.filter(md5=md5).exists():
                            pass
                        else:
                            Vulns(url=pymysql.escape_string(result['url']),
                                vuln_name=pymysql.escape_string(result['vuln_name']),
                                severity=result['severity'],
                                proof=pymysql.escape_string(result['proof']),
                                id_domain = self.id_domain,
                                md5=md5).save()
                logger.info("now done with bugscan script: {} and service == 'ip', ip={}".format(funcs[0], ip))


            for vfunc in self.verifyfuncs:
                _r = None
                try:
                    logger.info("now scanning: ip=[{}]\tport=[{}] with verify script: {}".format(ip, port, vfunc[0]))
                    _r = vfunc[1](ip, port, name, types=self.types)
                    logger.info("now done with verify script: {} and service == 'ip', ip={}, result={}".format(vfunc[0], ip, _r))
                except Exception as e:
                    logger.error("vfunc has error for: {}".format(repr(e)))
                if _r:
                    md5 = get_md5(_r['url'] + '|' + _r['vuln_name'])
                    if Vulns.objects.filter(md5=md5).exists():
                        pass
                    else:
                        Vulns(url=pymysql.escape_string(_r['url']),
                            vuln_name=pymysql.escape_string(_r['vuln_name']),
                            severity=_r['severity'],
                            proof=pymysql.escape_string(_r['proof']),
                            id_domain = self.id_domain,
                            md5=md5).save()


    def scan(self, threadnum=25):
        threads = []
        for t in xrange(threadnum):
            _x = threading.Thread(target=self._scanwork)
            threads.append(_x)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def pocscan(urlqueue, types='ip', id_domain=1):
    p = PocPlugin(urlqueue,types=types, id_domain=1)
    p.scan()



def SensitiveScan(url):
    args = ArgsConfig()
    resultQueue = Queue()
    s = InfoDisScanner(url=url, extion='php', args=args, resultQueue=resultQueue)
    s.scan()
    # print '-------------------------'
    # print 'done-----------------lenthofresultQueue: {}'.format(resultQueue.qsize())
    return resultQueue



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



def save2sql(sql):
    try:
        s = MySQLUtils()
        s.insert(sql)
        s.close()
    except Exception as e:
        logger.error('Save2Sql Error Happend: {}'.format(repr(e)))





STATIC_EXT = ["f4v","bmp","bz2","css","doc","eot","flv","gif"]
STATIC_EXT += ["gz","ico","jpeg","jpg","js","less","mp3", "mp4"]
STATIC_EXT += ["pdf","png","rar","rtf","swf","tar","tgz","txt","wav","woff","xml","zip"]


BLACK_LIST_PATH = ['logout', 'log-out', 'log_out']


BLACK_LIST_HOST = ['safebrowsing.googleapis.com', 'shavar.services.mozilla.com',]
BLACK_LIST_HOST += ['detectportal.firefox.com', 'aus5.mozilla.org', 'incoming.telemetry.mozilla.org',]
BLACK_LIST_HOST += ['incoming.telemetry.mozilla.org', 'addons.g-fox.cn', 'offlintab.firefoxchina.cn',]
BLACK_LIST_HOST += ['services.addons.mozilla.org', 'g-fox.cn', 'addons.firefox.com.cn',]
BLACK_LIST_HOST += ['versioncheck-bg.addons.mozilla.org', 'firefox.settings.services.mozilla.com']
BLACK_LIST_HOST += ['blocklists.settings.services.mozilla.com', 'normandy.cdn.mozilla.net']
BLACK_LIST_HOST += ['activity-stream-icons.services.mozilla.com', 'ocsp.digicert.com']
BLACK_LIST_HOST += ['safebrowsing.clients.google.com', 'safebrowsing-cache.google.com', 'localhost']
BLACK_LIST_HOST += ['127.0.0.1']

class TURL(object):
    """docstring for TURL"""
    def __init__(self, url):
        super(TURL, self).__init__()
        self.url = url
        self.format_url()
        self.parse_url()
        if ':' in self.netloc:
            tmp = self.netloc.split(':')
            self.host = tmp[0]
            self.port = int(tmp[1])
        else:
            self.host = self.netloc
            self.port = 80
        if self.start_no_scheme:
            self.scheme_type()

        self.final_url = ''
        self.url_string()

    def parse_url(self):
        parsed_url = urlparse.urlparse(self.url)
        self.scheme, self.netloc, self.path, self.params, self.query, self.fragment = parsed_url

    def format_url(self):
        if (not self.url.startswith('http://')) and (not self.url.startswith('https://')):
            self.url = 'http://' + self.url
            self.start_no_scheme = True
        else:
            self.start_no_scheme = False

    def scheme_type(self):
        if is_http(self.host, self.port) == 'http':
            self.scheme = 'http'

        if is_https(self.host, 443) == 'https':
            self.scheme = 'https'
            self.port = 443

    @property
    def get_host(self):
        return self.host

    @property
    def get_port(self):
        return self.port

    @property
    def get_scheme(self):
        return self.scheme

    @property
    def get_path(self):
        return self.path

    @property
    def get_query(self):
        """
        return query
        """
        return self.query

    @property
    def get_dict_query(self):
        """
        return the dict type query
        """
        return dict(urlparse.parse_qsl(self.query))

    @get_dict_query.setter
    def get_dict_query(self, dictvalue):
        if not isinstance(dictvalue, dict):
            raise Exception('query must be a dict object')
        else:
            self.query = urllib.urlencode(dictvalue)

    @property
    def get_filename(self):
        """
        return url filename
        """
        return self.path[self.path.rfind('/')+1:]

    @property
    def get_ext(self):
        """
        return ext file type
        """
        fname = self.get_filename
        ext = fname.split('.')[-1]
        if ext == fname:
            return ''
        else:
            return ext

    def is_ext_static(self):
        """
        judge if the ext in static file list
        """
        if self.get_ext in STATIC_EXT:
            return True
        else:
            return False

    def is_block_path(self):
        """
        judge if the path in black_list_path
        """
        for p in BLACK_LIST_PATH:
            if p in self.path:
                return True
        else:
            return False

    def url_string(self):
        data = (self.scheme, self.netloc, self.path, self.params, self.query, self.fragment)
        url = urlparse.urlunparse(data)
        self.final_url = url
        return url

    def __str__(self):
        return self.final_url

    def __repr__(self):
        return '<TURL for %s>' % self.final_url



def LogUtil(path='/tmp/webscanner.log', name='test'):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    #create formatter
    formatter = logging.Formatter(fmt=u'[%(asctime)s] [%(levelname)s] [%(funcName)s] %(message)s ')

    # create console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # create file
    file_handler = logging.FileHandler(path, encoding='utf-8')
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger


logger = LogUtil()


class THTTPJOB(object):
    """docstring for THTTPJOB"""
    def __init__(self,
                url,
                method='GET',
                data=None,
                files=False,
                filename='',
                filetype='image/png',
                headers=None,
                block_static=True,
                block_path = True,
                allow_redirects=False,
                verify=False,
                timeout = 10,
                is_json=False,
                time_check=True):
        """
        :url: the url to requests,
        :method: the method to request, GET/POST,
        :data: if POST, this is the post data, if upload file, this be the file content
        :files: if upload files, this param is True
        :filename: the upload filename
        :filetype: the uplaod filetype
        :headers: the request headers, it's a dict type,
        :block_static: if true, will not request the static ext url
        :block_path: if true, will not request the path in BLACK_LIST_PATH
        :allow_redirects: if the requests will auto redirects
        :verify: if verify the cert
        :timeout: the request will raise error if more than timeout
        :is_json: if the data is json
        :time_check: if return the check time
        """
        super(THTTPJOB, self).__init__()
        if isinstance(url, TURL):
            self.url = url
        else:
            self.url = TURL(url)

        self.method = method
        self.data = data
        self.files = files
        self.filename = filename
        self.filetype = filetype
        # self.connect_error = False
        self.block_path = block_path
        self_headers = {
            'User-Agent': ('Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)'
                'Chrome/38.0.2125.111 Safari/537.36 IQIYI Cloud Security Scanner tp_cloud_security[at]qiyi.com'),
            'Connection': 'close',
        }
        self.ConnectionErrorCount = 0
        self.headers = headers if headers else self_headers
        self.block_static = block_static
        self.allow_redirects = allow_redirects
        self.verify = verify
        self.is_json = is_json
        self.timeout = timeout
        if self.method == 'GET':
            self.request_param_dict = self.url.get_dict_query
        else:
            if self.is_json:
                self.request_param_dict = json.loads(self.data)
            else:
                self.request_param_dict = dict(urlparse.parse_qsl(self.data))


    def request(self):
        """
        return status_code, headers, htmlm, time_check
        """
        if self.block_static and self.url.is_ext_static():
            self.response = requests.Response()
            return -1, {}, '', 0
        elif self.block_path and self.url.is_block_path():

            self.response = requests.Response()
            return -1, {}, '', 0
        elif self.url.get_host in BLACK_LIST_HOST:
            # print "found {} in black list host".format(self.url.get_host)
            self.response = requests.Response()
            return -1, {}, '', 0
        elif self.ConnectionErrorCount >=3 :
            return -1, {}, '', 0

        else:
            start_time = time.time()
            try:
                if self.method == 'GET':
                    self.url.get_dict_query = self.request_param_dict
                    self.response = requests.get(
                        self.url.url_string(),
                        headers = self.headers,
                        allow_redirects = self.allow_redirects,
                        verify = self.verify,
                        timeout = self.timeout,
                        )
                    end_time = time.time()
                else:
                    if not self.files:
                        self.data = self.request_param_dict
                        self.response = requests.post(
                            self.url.url_string(),
                            data = self.data,
                            headers = self.headers,
                            verify = self.verify,
                            allow_redirects = self.allow_redirects,
                            timeout = self.timeout,
                            )
                    else:
                        # print "------------------"
                        f = {'file' : (self.filename, self.data, self.filetype)}
                        self.response = requests.post(
                            self.url.url_string(),
                            files=f,
                            headers=self.headers,
                            verify=False,
                            allow_redirects=self.allow_redirects,
                            # proxies={'http': '127.0.0.1:8080'},
                            timeout=self.timeout,
                            )
                    end_time = time.time()
            except Exception as e:
                print "[lib.common] [THTTPJOB.request] {}".format(repr(e))
                end_time = time.time()
                self.ConnectionErrorCount += 1
                return -1, {}, '', 0
            self.time_check = end_time - start_time
            return self.response.status_code, self.response.headers, self.response.text, self.time_check

    def __str__(self):
        return "[THTTPOBJ] method={} url={} data={}".format(self.method, self.url.url_string(), self.data )





def is_http(url, port=None):
    """
    judge if the url is http service
    :url  the host, like www.iqiyi.com, without scheme
    """
    if port is None: port = 80
    service = ''
    try:
        conn = httplib.HTTPConnection(url, int(port), timeout=10)
        conn.request('HEAD', '/')
        conn.close()
        service = 'http'
    except Exception as e:
        print "[lib.common] [is_http] {}".format(repr(e))

    return service

def is_https(url, port=None):
    """
    judge if the url is https request
    :url  the host, like www.iqiyi.com, without scheme
    """
    ssl._create_default_https_context = ssl._create_unverified_context
    if port is None: port = 443
    service = ''
    try:
        conn = httplib.HTTPSConnection(url, int(port), timeout=10)
        conn.request('HEAD', '/')
        conn.close()
        service = 'https'
    except Exception as e:
        print "[lib.common] [is_https] {}".format(repr(e))

    return service


def is_json(data):
    if not data:
        return False
    try:
        json.loads(data)
        return True
    except:
        return False


class Pollution(object):
    """
    this class aim to use the payload
    to the param in requests
    """
    def __init__(self, query, payloads, pollution_all=False, isjson=False, replace=True):
        """
        :query: the url query part
        :payloads:  List, the payloads to added in params
        :data: if url is POST, the data is the post data
        """
        self.payloads = payloads
        self.query = query
        self.isjson = isjson
        self.replace = replace
        self.pollution_all = pollution_all
        self.polluted_urls = []

        if type(self.payloads) != list:
            self.payloads = [self.payloads,]

    def pollut(self):
        if self.isjson:
            query_dict = dict(urlparse.parse_qsl(self.query, keep_blank_values=True))
        else:
            query_dict = dict(urlparse.parse_qsl(self.query, keep_blank_values=True))

        for key in query_dict.keys():
            for payload in self.payloads:
                tmp_qs = query_dict.copy()
                if self.replace:
                    tmp_qs[key] = payload
                else:
                    tmp_qs[key] = tmp_qs[key] + payload
                self.polluted_urls.append(tmp_qs)

    def payload_generate(self):
        #print self.payloads
        if self.pollution_all:
            pass
        else:
            self.pollut()
            return self.polluted_urls






class Url:

    @staticmethod
    def url_parse(url):
        return urlparse.urlparse(url)

    @staticmethod
    def url_unparse(data):
        scheme, netloc, url, params, query, fragment = data
        if params:
            url = "%s;%s" % (url, params)
        return urlparse.urlunsplit((scheme, netloc, url, query, fragment))

    @staticmethod
    def qs_parse(qs):
        return dict(urlparse.parse_qsl(qs, keep_blank_values=True))

    @staticmethod
    def build_qs(qs):
        return urllib.urlencode(qs).replace('+', '%20')

    @staticmethod
    def urldecode(qs):
        return urllib.unquote(qs)

    @staticmethod
    def urlencode(qs):
        return urllib.quote(qs)


class MySQLUtils():
    host = '127.0.0.1'
    port = 3306
    username = 'root'
    password = ''
    db = 'webscanner'

    def __init__(self):
        self.conn = pymysql.connect(host=MySQLUtils.host,
                             user=MySQLUtils.username,
                             password=MySQLUtils.password,
                             charset='utf8mb4',
                             db=MySQLUtils.db)

    def insert(self, sql):
        with self.conn.cursor() as cursor:
            cursor.execute(sql)
            self.conn.commit()

    def fetchone(self, sql):
        data = ''
        with self.conn.cursor() as cursor:
            cursor.execute(sql)
            data = cursor.fetchone()
        return data

    def fetchall(self, sql):
        data = []
        with self.conn.cursor() as cursor:
            cursor.execute(sql)
            data = cursor.fetchall()
        return data

    def close(self):
        self.conn.close()


def random_str(length=8):
    s = string.lowercase + string.uppercase + string.digits
    return "".join(random.sample(s, length))


REDIS_DB = '0'
REDIS_HOST = '127.0.0.1'
REDIS_PASSWORD = ''
SQLI_TIME_QUEUE = 'time:queue'

class RedisUtil(object):
    def __init__(self, db, host, password='', port=6379):
        self.db = db
        self.host = host
        self.password = password
        # self.taskqueue = taskqueue
        self.port = port
        self.connect()

    def connect(self):
        try:
            self.conn = redis.StrictRedis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password
            )
        except Exception as e:
            print repr(e)
            print "RedisUtil Connection Error"
            self.conn = None
        # finally:
            # return conn


    @property
    def is_connected(self):
        try:
            if self.conn.ping():
                return True
        except:
            print "RedisUtil Object Not Connencd"
            return False


    def task_push(self, queue, data):
        self.conn.lpush(queue, (data))

    def task_fetch(self, queue):
        return self.conn.lpop(queue)


    @property
    def task_count(self, queue):
        return self.conn.llen(queue)


    def set_exist(self, setqueue, key):
        return self.conn.sismember(setqueue, key)

    def set_push(self, setqueue, key):
        self.conn.sadd(setqueue, key)

    #def close(self):
    #    self.conn.close()


class PortCrack(object):
    def __init__(self, port=None, ip=None, service=None):
        self.port = port
        self.service = service
        self.ip = ip
        self.username = 'username.txt'
        self.password = 'password.txt'
        self.vul_list = []

    def get_path(self):
        here = path.split(path.abspath(__file__))[0]
        return here

    def randStr(self, length=8):
        allchar = string.lowercase + string.uppercase + string.digits
        return ''.join(random.sample(allchar, length))

    def work(self):
        if self.ip is None or self.port is None or self.service is None:
            return
        cmd = 'hydra -L {uname} -P {passwd} -t 4 -s {port}  -f -o {resultfile} {server} {service} >/dev/null 2>&1'
        here = self.get_path()
        uname = path.join(here, 'util/' ,self.username)
        passwd = path.join(here, 'util/',self.password)
        resultfile = '/tmp/{}.txt'.format(self.randStr())

        r_cmd = cmd.format(uname=uname,
                        passwd=passwd,
                        port=self.port,
                        resultfile=resultfile,
                        server=self.ip,
                        service=self.service
                        )
        logger.info('cmd={}'.format(r_cmd))
        code = system(r_cmd)
        self.parse_result_hydra(code, resultfile)

    def parse_result_hydra(self, ret, tmpfile):
        """
        [21][ftp] host: 10.15.154.142   login: ftpftp   password: h123123a
        """
        try:
            if not path.exists(tmpfile):
                return
            for line in open(tmpfile, 'r').readlines():
                line = str(line).strip('\r\n')
                if not line:
                    continue
                m = re.findall(r'host: (\S*).*login: (\S*).*password:(.*)', line)
                if m and m[0] and len(m[0]) == 3:
                    username = m[0][1]
                    password = m[0][2].strip()
                    msg = '{service}://{uname}:{passwd}@{ip}:{port}'
                    self.vul_list.append(msg.format(
                        service=self.service,
                        uname=username,
                        passwd=password,
                        ip=self.ip,
                        port=self.port))
                    # self.push_vul(username, password, line)
            # return len(self.vul_list)
        except Exception as e:
            logger.error('[PortCrackBase][parse_result_hydra] Exception %s' % e)



def crackWork(item):
    port, ip, service = item
    a = PortCrack(port=port, ip=ip, service=service)
    a.work()
    if a.vul_list:
        return a.vul_list
    else:
        return None



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
    #a = InfoLeakScan("http://211.151.158.132")
    #a.scan()
    #while not a.result.empty():
    # #    print a.result.get()
    # print is_http('www.iqiyi.com')
    # print is_https('top.iqiyi.com')
    a = PortCrack(port=3306, service='mysql',ip='127.0.0.1')
    print a.vul_list()
