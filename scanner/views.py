# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# from django.shortcuts import render


from django.shortcuts import render
from django.http import Http404
from django.shortcuts import render_to_response
from django.shortcuts import redirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.http import JsonResponse
from django.http import HttpResponse
from django.http import StreamingHttpResponse
from django.template import RequestContext
from django.http import HttpResponseRedirect
from django.core.files.base import ContentFile
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.core.paginator import Paginator
from tasks import task_masscan, nmap_scan, get_title, sensitivescan, pocverify
from models import *
from commons import *

# Create your views here.

@login_required(login_url='/login/')
def index(request):
    print "request.user= {}".format(request.user.username)
    #print dir(request.user)
    return render(request, "index.html")

@login_required(login_url='/login/')
def create(request):
    return render(request, "create.html")

@login_required(login_url='/login/')
def createtask(request):
    """
    this function aim to create task, i.e. add url and ips to database
    but on test, it's vaste lots of time .
    so next version, consider use celery to do the work
    """
    if request.method != "POST":
        raise Http404("Only POST Support")
    domain = request.POST["domain"]
    if not domain:
        raise Http404("domain required!")

    #judge if the domain in databases, if not save it to database
    domain_obj, created = Domain.objects.get_or_create(domain=domain)

    # get id_domain
    id_domain = domain_obj.id

    #print "id_domain= {}".format(id_domain)

    ips = request.POST["ips"]
    ips = ips.split(",")
    files = request.FILES.get("files", "")
    ip_cidr = []
    if files:
        # deal files for now ,just think it's subdomainsbrtue result
        # file_content = ContentFile(files.read())
        lines = files.readlines()
        #print "======"
        # print domain
        # print lines[0]
        urls, iplist = parse_file(lines)
        # print type(files.readlines())
        # print files.read()
        # print urls, ips_infile
        #print urls[0]
        #print "============="
        # save the urls to Subdomains
        for url in urls:
            subdomain_obj, created = Subdomains.objects.get_or_create(
                subdomain=url,
                id_domain=id_domain,
                )

        ip_cidr = get_ip_target(iplist)
        # logger.info("[createtask] ip_cidr={}".format(ip_cidr))
    if ips not in ip_cidr:
        ip_cidr.extend(ips)


    #print ip_cidr
    try:
        for i in ip_cidr:
            if i:
                task_masscan.delay(i, id_domain)
    except Exception as e:
        return Http404("IP CIDRS MUST BE A LIST BOJECTS")

    return redirect(reverse("index"))
    # first save it to databases and the use masscan to scan


@login_required(login_url='/login/')
def showdomainip(request):
    if "domain" in request.GET:
        domain = request.GET["domain"]
    else:
        domain = None
    if domain:
        domain_id = Domain.objects.get(id=domain)
        domain_id = domain_id.id
    else:
        domain_id = 1
    ip_objects = PortTable.objects.filter(id_domain=domain_id)

    # get page
    # split page
    paginator = Paginator(ip_objects, 20)  # 实例化一个分页对象

    page = request.GET.get('page', '1')  # 获取页码
    page = int(page)
    try:
        ip_objects = paginator.page(page)  # 获取某页对应的记录
    except PageNotAnInteger:  # 如果页码不是个整数
        ip_objects = paginator.page(1)  # 取第一页的记录
    except EmptyPage:  # 如果页码太大，没有相应的记录
        ip_objects = paginator.page(paginator.num_pages)  # 取最后一页的记录

    return render(request, 'showdomainip.html', {'ipobjs': ip_objects})


@login_required(login_url='/login/')
def domains(request):
    """
     this function show the domains, i.e.  id<=>domain
     and remains the action like scan, delete and so on
    """
    domainobjs = Domain.objects.all()
    paginator = Paginator(domainobjs, 25)
    page = request.GET.get("page", "1")
    page = int(page)
    try:
        objs = paginator.page(page)
    except PageNotAnInteger:
        objs = paginator.page(1)
    except EmptyPage:
        objs = paginator.page(paginator.num_pages)
    return render(request, "domains.html", {"objs": objs})


@login_required(login_url='/login/')
def scandomain(request):
    try:
        assert "id" in request.GET
    except Exception as e:
        return Http404("error param: {}".format(repr(e)))

    id_domain = request.GET["id"]
    try:
        id_domain = int(id_domain)
    except Exception:
        return Http404("must integer")

    # first get the all subdomains and then
    # use infoleak to scan the info
    subdomains = Subdomains.objects.filter(id_domain=id_domain)
    for s in subdomains:
        sensitivescan.delay(s.subdomain, id_domain)
        print "[view] [scandomain] [line160] http={}".format(s.subdomain)
        #sensitivescan.delay(s, id_domain)

    # second get the ip talbes
    portobjs = PortTable.objects.filter(id_domain=id_domain).values_list('ip', 'port', 'name')
    iplist = set()
    httplist = []
    for obj in portobjs:
        ip, port, name = obj
        iplist.add(ip)
        #if is_http(ip, port) == 'http':
        if str(port) in ("443", "8443") or name.find("https") > -1:
            h = "https://{}:{}".format(ip, port)
        else:
            h = "http://{}:{}".format(ip, port)
            httplist.append(h)

    for obj in portobjs:
        ip, port, name = obj
        target = (ip, port, name)
        pocverify.delay(target, id_domain)


    # iplist = list(iplist)
    # ip_cidr = get_ip_target(iplist)
    # ip_cidr to use script scan
    # for i in ip_cidr[:2]:
        # script load and scan
    #     pocverify.delay(i, id_domain, iscidr=True)
    # # use infoleak to scan the http service
    for http in httplist:
    #     # print "[view] [scandomain] [line182] http={}".format(http)
        sensitivescan.delay(http, id_domain)
        # pass

    return redirect("/")
    # return HttpResponse("httplist={}\nip_cidr={}".format(httplist, ip_cidr))


@login_required(login_url='/login/')
def nmapscan(request):
    if "id" not in request.GET:
        return redirect("/")
    domainid = request.GET.get("id")
    portobjs = PortTable.objects.filter(id_domain=domainid)
    portqueue = []
    id_domain = int(domainid)
    for obj in portobjs:
        o = (obj.ip, obj.port)
        portqueue.append(o)

    #return HttpResponse(str(portqueue))
    nmap_scan.delay(portqueue, id_domain)
    return redirect("/")


@login_required(login_url='/login/')
def updatehttptitle(request):
    """
    this function aim to update the http title
    i.e. the fetch the <title>.*</title> or first 200 bytes

    """
    if "id" not in request.GET or (not request.GET["id"].isdigit()):
        return redirect("/")
    id_domain = int(request.GET["id"])
    portobjs = PortTable.objects.filter(id_domain=id_domain)
    portobjlist = []
    for obj in portobjs:
        o = (obj.id, obj.ip, obj.port)
        portobjlist.append(o)

    get_title.delay(portobjlist)
    return redirect("/")


@login_required(login_url='/login/')
def showvulns(request):
    if "id_domain" not in request.GET:
        id_domain = 1
    else:
        try:
            id_domain = int(id_domain)
        except:
            return Http404("param format error")

    vulnobj = Vulns.objects.filter(id_domain=id_domain)
    # get page
    # split page
    paginator = Paginator(vulnobj, 20)  # 实例化一个分页对象

    page = request.GET.get('page', '1')  # 获取页码
    page = int(page)
    try:
        vulnobj = paginator.page(page)  # 获取某页对应的记录
    except PageNotAnInteger:  # 如果页码不是个整数
        vulnobj = paginator.page(1)  # 取第一页的记录
    except EmptyPage:  # 如果页码太大，没有相应的记录
        vulnobj = paginator.page(paginator.num_pages)  # 取最后一页的记录

    return render(request, 'vulns.html', {'ipobjs': vulnobj})



@login_required(login_url='/login/')
def deleteopt(request):
    # print dir(request)

    try:
        if "id" not in request.GET or "table" not in request.GET:
            return Http404("parameter error")
        if request.GET["table"] not in ("vulns", "port", "domain"):
            return Http404("parameter error")
        deleteid = int(request.GET["id"])
        table = request.GET["table"]
        if table == "vulns":
            #print "id={}&table={}".format(deleteid, table)
            Vulns.objects.filter(id=deleteid).delete()
        elif table == "port":
            PortTable.objects.filter(id=deleteid).delete()
        elif table == "domain":
            Domain.objects.filter(id=deleteid).delete()
        else:
            raise Exception("unknow table")
    except Exception as e:
        return Http404("error happend")

    result = {'success':True}
    return JsonResponse(result)


@login_required(login_url='/login/')
def guesscms(request):
    """
    this function aim to invoke the celery function
    to guess cms type.
    if cms type is not null, ingore it
    """
    if ("id" not in request.GET) or (request.GET['id'].isdigit() is False):
        return redirect("/")
    id_domain = int(request.GET['id'])
    # first get the subdomains
    subdomainobjs = Subdomains.objects.filter(id_domain=id_domain).filter(cmstype__isnull=True)
    for s in subdomainobjs[:5]:
        CMSGuess.delay(s.subdomain, s.id, isip=False)

    return HttpResponse(len(subdomainobjs))

