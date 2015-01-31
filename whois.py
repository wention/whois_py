#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
import re
import idna
import json
import socket
import threading
import traceback

def init():
    global tld_lst
    global whois_lst
    try:
        fd = open("data/tld.json","rb")
        data = fd.read()
        tld_lst = json.loads(data)
        fd.close()

        fd = open("data/whois.json","rb")
        data = fd.read()
        whois_lst = json.loads(data)
        fd.close()
    except:
        print traceback.format_exc()

def is_dom(domain, chk_tld = 0):
    #检测 tld 是否是有效域名(符合域名命名规则的)
    #chk_tld  check if it is top level domain if set to nonzero or True
    dom = domain.split('.')
    ndot = domain.count(".")

    if (chk_tld):
        if (ndot > 2):
            return False
        elif (ndot > 1):
            if (tld_lst.has_key('.' + dom[ndot]) and tld_lst['.' + dom[ndot]]["type"] == "country-code" and (tld_lst.has_key('.' + dom[ndot-1]) or len(dom[ndot-1])==2 )):
                return True
            else:
                return False
        elif (ndot == 0):
            return False
        return True
    else:
        return tld_lst.has_key('.' + dom[ndot])


def parse_dom(url, get_tld = 0):
    dom = ""
    if (url):
        m = re.search(r"[0-9a-zA-Z\x80-\xff\-\.]+\.[a-zA-Z\x80-\xff]+", url)
        if (m):
            if(get_tld):
                #取出顶级域名
                tld  = m.group().split('.')
                ndot = m.group().count(".")

                #检证是否是有效域名
                if (tld_lst.has_key('.' + tld[ndot])):
                    if (ndot > 1):
                        if(tld_lst['.' + tld[ndot]]["type"] == "country-code" and (tld_lst.has_key('.' + tld[ndot-1]) or len(tld[ndot-1])==2 )):
                            return ".".join(tld[-3:])
                    return ".".join(tld[-2:])
            else:
                #取出域名　(符合域名命名规则的)
                return m.group()
    return False

def whois_query(query, server):
    try:
        respons = ""

        sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sockfd.settimeout(10)
        sockfd.connect((server,43))
        sockfd.send(query + "\r\n")
        while 1:
            n = sockfd.recv(4096)
            respons += n
            if n == "" or n ==None:
                break
        sockfd.close()

        return respons
    except socket.timeout:
        print "Socket Error: timeout"
        return whois_query(query, server)
    except:
        print "Socket Error: unknow"

def get_tld_whois(dom):
    # 向 IANA 查询 域名管理机构 whois 服务器
    respons = whois_query(dom, "whois.iana.org")
    begin   = respons.find("whois:")
    if (begin > 0):
        begin  += respons[begin:].find("whois.")
        end     = respons[begin:].find("\n")
        return respons[begin:begin + end]
def get_server(dom):
    # 从 tld.json 数据中检索出 想应的 whois 服务器
    pass

def whois(dom):
    #主程
    server  = get_domain_whois(dom)
    respons = whois_query(dom, server)

    return respons

def worker():
    global crtjob
    while True:
        if (crtjob > length -1):
            break
        mutex.acquire()
        th = crtjob
        tld = jobs[crtjob]
        crtjob +=1
        mutex.release()
        print str(th) +"\t"+ str(threading.activeCount()) + "\t%s\t\t%s" %(tld, get_tld_whois(tld))

if __name__ == "__main__":
    global mutex,jobs,crtjob,length
    threads = []
    reload(sys)
    sys.setdefaultencoding('utf8')
    print sys.getdefaultencoding()
    print "initailizing ....."
    init()
    print "done"
    workers = 50
    mutex = threading.Lock()
    jobs = tld_lst.keys()
    crtjob = 0
    length = len(jobs)
    for x in xrange(0, workers):
        threads.append(threading.Thread(target=worker))
    # 启动所有线程
    for t in threads:
        t.start()
    # 主线程中等待所有子线程退出
    for t in threads:
        t.join()
