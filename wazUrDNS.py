#!/usr/bin/env python
# -*- coding: utf8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
#
# This tool needs:
# * list of IP addresses
# * list of already known domain names (might be empty)
# * list of prefixes to brute-foces (such as "www", "old", "autodiscover")

from dnsutil import is_public_suffix, get_subdomains, get_sublabels, get_main_domain, certificate_transparency_lookup
from queue import PriorityQueue
from copy import deepcopy
import time
import threading
import sys
import dns.resolver
import random
import binascii

# CONFIG SECTION

CONF = { 
   "NS":False,         # do NS, should probably be False, as it leads to high number of false positives
   "A" :True,          # do A, should be True
   "AAAA": True,       # do AAAA, should be True
   "MX": True,         # do MX
   "TXT": True,        # do TXT, can be False
   "PTR": True,        # do reverse lookups, should be True 
   "CNAME": True,      # do CNAME
   "CERTTRANS" : True, # certificate transparency via crt.sh, only for domains one below TLD, should be True
   "add-new-ips":False,
   "bruteforce-prefixes":True,
   "mutate-ending-numbers":True, # if there is mail01, try also mail02...mail09 as well as mail11...mail91 (and if any of those name exists, recursively try others, too)

#   "bruteforce-prefixes-with-new":False,
#   "parse-mx":True,
#   "parse-spf":True,
   "RESOLVERS":["1.1.1.1","4.2.2.1", "8.8.8.8", "9.9.9.10"],
   "DELAY": 0.1,
   "MAXDEPTH":10,
   }


datalock = threading.Lock()   # lock for accessing global variables
outputlock = threading.Lock() # lock to serialize console output
verbosity = 2 
STARTTIME = time.perf_counter()
q = PriorityQueue()

# returns if a is a subdomain of b
def is_subdomain(a,b):
    return a.endswith("."+b)

def log(sev, msg):
    loglevel = [ "WARN: ", "INFO: ", "DEBUG:"]
    if sev <= verbosity:
        # if msg has a linebreak, fix intendation
        msg = msg.replace('\n', '\n'+' '*(5+1+2))
        with outputlock:
            print("%s  %s" % (loglevel[sev], msg), file=sys.stderr)

def load(filename):
    with open(filename) as f:
        return [x.strip('\n') for x in f.readlines()]


initdomains = load("domains.txt")
initips = load("ips.txt")
initprefixes = load("prefixes.txt") 
blacklist = load("blacklist.txt")
lookup_cache = {}
domains = deepcopy(initdomains)
ips = deepcopy(initips)
prefixes = deepcopy(initprefixes)
WILDCARD_TEST = 'wildcard-'+''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for _ in range(8)) 

def is_blacklisted(d):
    d="."+d
    for b in blacklist:
        if d.endswith(b):
            return True
    return False

def is_wildcard(resolver, arg, typ):
    #log(2, "")
    #log(2, f"is_wildcard({resolver}, {arg}, {typ}")
    s = get_subdomains(arg, include_self=False)
    if s == []: return False
    s = WILDCARD_TEST + "." + s[0]
    with datalock:
        if (s, typ) in lookup_cache:
            is_wildcard = (lookup_cache[(s,typ)] != None)
            #log(2, f"wildcard status of {(s,typ)} was cached, is {is_wildcard}")
            return is_wildcard
    if is_wildcard(s[0], arg,typ):
        return True
    # not yet known, we need to check
    with datalock:
        lookup_cache[(s,typ)] = None
    try:
        result = resolver.resolve(s, typ)
    except:
        #except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers):
        result = None
    #log(1, f"wildcard status of {(s,typ)} is {result != None}")
    with datalock:
        lookup_cache[(s,typ)] = result
    return result != None

def smartresolve(resolver, dns, typ):
    if not is_wildcard(resolver, dns,typ):
        return resolver.resolve(dns,typ)
    return []

def _on_new_name(depth, d):
    log(2, f"_on_new_name({depth}, {d})")
    if CONF["CERTTRANS"]:
        if not is_blacklisted(d): 
            q.put((depth, ("CERTTRANS", get_main_domain(d))))
    for s in get_subdomains(d):
        if CONF["A"]:     q.put((depth, ("A",s)))
        if CONF["AAAA"]:  q.put((depth, ("AAAA",s)))
        if CONF["MX"]:    q.put((depth, ("MX",s)))
        if CONF["NS"]:    q.put((depth, ("NS",s)))
        if CONF["TXT"]:   q.put((depth, ("TXT",s)))
        if CONF["CNAME"]: q.put((depth, ("CNAME",s)))
        # we don't want to enumerate AWS, Cloudflare etc.
        if not is_blacklisted(s):
            if CONF["bruteforce-prefixes"]:
                for p in initprefixes:
                    if CONF["A"]:     q.put((depth+1,("A",p+"."+s)))
                    if CONF["AAAA"]:  q.put((depth+1,("AAAA",p+"."+s)))
                    if CONF["MX"]:    q.put((depth+1,("MX",p+"."+s)))
                    if CONF["NS"]:    q.put((depth+1,("NS",p+"."+s)))
                    if CONF["TXT"]:   q.put((depth+1,("TXT",p+"."+s)))
                    if CONF["CNAME"]: q.put((depth+1,("CNAME",p+"."+s)))
            if CONF["mutate-ending-numbers"]:
                # find the last character before the first .
                index = len(s.split(".")[0])-1
                while index>=0 and ord('0') <= ord(s[index]) <= ord('9'):
                    for i in range(10):
                        new_sub = s[:index]+str(i)+s[index+1:]
                        if new_sub != s:
                            if CONF["A"]:     q.put((depth, ("A",new_sub)))
                            if CONF["AAAA"]:  q.put((depth, ("AAAA",new_sub)))
                            if CONF["MX"]:    q.put((depth, ("MX",new_sub)))
                            if CONF["NS"]:    q.put((depth, ("NS",new_sub)))
                            if CONF["TXT"]:   q.put((depth, ("TXT",new_sub)))
                            if CONF["CNAME"]: q.put((depth, ("CNAME",new_sub)))
                    index=index-1

def _on_new_ip(depth, ip, force_add=False):
    log(2, f"_on_new_ip({depth}, {ip}, {force_add})")
    if CONF["add-new-ips"] or force_add:
        with datalock:
            ips.append(ip)
        q.put((depth, ("PTR", ip)))

def on_A_result(depth, d, result):
    log(2, f"on_A_result({depth}, {d}, {result})")
    _on_new_name(depth, d)
    _on_new_ip(depth, result)
def on_AAAA_result(depth, d, result):
    log(2, f"on_AAAA_result({depth}, {d}, {result})")
    _on_new_name(depth, d)
    _on_new_ip(depth, result)
def on_PTR_result(depth, d, result):
    log(2, f"on_AAAA_result({depth}, {d}, {result})")
    _on_new_name(depth, result)
def on_TXT_result(depth, d, result):
    log(2, f"on_TXT_result({depth}, {d}, {result})")
    # TODO: parse SPF and other stuff ...
def on_CNAME_result(depth, d, result):
    log(2, f"on_CNAME_result({depth}, {d}, {result})")
    _on_new_name(depth, d)
    _on_new_name(depth, result)
def on_MX_result(depth, d, result):
    log(2, f"on_MX_result({depth}, {d}, {result})")
    _on_new_name(depth, d)
    # TODO: parse MX
def on_NS_result(depth, d, result):
    log(2, f"on_NS_result({depth}, {d}, {result})")
    _on_new_name(depth, d)
    # TODO: parse result
def on_CERTTRANS_result(depth, d, result):
    log(2, f"on_CERTTRANS_result({depth}, {d}, {result})")
    _on_new_name(depth, result)

def worker(r):
    global lookup_cache
    log(1,f"worker for resolver {r} started")
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [r]
    while True:
        depth, workitem = q.get()
        if depth > CONF["MAXDEPTH"]:
            log(2, "ignoring {workitem} because level too deep")
            continue
        typ, arg = workitem
        with datalock:
            if not workitem in lookup_cache:
                lookup_cache[(typ,arg)] = None 
                skip=False
            else:
                skip=True
        if skip:
            log(3, f"{workitem} already done or started: {lookup_cache[(typ,arg)]}")
            q.task_done()
            continue
        log(1, f"depth {depth} workitem {workitem} queuesize {q.qsize()}")
        try:
            if typ == "A":
                answer = smartresolve(resolver, arg, 'A')
                for a in answer: on_A_result(depth+1, arg, a.to_text()) 
            elif typ == "PTR":
                arg = dns.reversename.from_address(arg)
                answer = resolver.resolve(arg, 'A')
                for a in answer: on_PTR_result(depth+1, arg, a.to_text())
            elif typ == "AAAA":
                answer = smartresolve(resolver, arg, 'AAAA')
                for a in answer: on_AAAA_result(depth+1, arg, a.to_text()) 
            elif typ == "TXT":
                answer = smartresolve(resolver, arg, 'TXT')
                for a in answer: on_TXT_result(depth+1, arg, a.to_text()) 
            elif typ == "CNAME":
                answer = smartresolve(resolver, arg, 'CNAME')
                for a in answer: on_CNAME_result(depth+1, arg, a.to_text()) 
            elif typ == "MX":
                answer = smartresolve(resolver, arg, 'MX')
                for a in answer: on_MX_result(depth+1, arg, a.to_text()) 
            elif typ == "NS":
                answer = smartresolve(resolver, arg, 'NS')
                for a in answer: on_NS_result(depth+1, arg, a.to_text()) 
            elif typ == "CERTTRANS":
                answer = certificate_transparency_lookup(arg)
                for a in answer: on_CERTTRANS_result(depth+1, arg, a) 
            else:
                raise ValueError("unknown workitem {workitem}")
        except:
            # except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers):
            answer = None
        with datalock:
            lookup_cache[(typ,arg)] = answer
        q.task_done()
        time.sleep(CONF["DELAY"] + random.random()/10)

    time.sleep(4)
    pass

# add initial data with priority 0
for ip in initips: _on_new_ip(0, ip, force_add=True)
for d in initdomains: _on_new_name(0, d)

threads = []
for r in CONF["RESOLVERS"]:
    t = threading.Thread(target=worker, daemon=True, args=(r,))
    t.start()
    threads.append(t)

#for t in threads: t.join()

q.join()

log(1, "no more work! elapsed time: %s seconds" % round(time.perf_counter() - STARTTIME,2))
for a,b in lookup_cache.items():
    if b != None:
        typ,d=a
        for i in b: 
            print(d,typ,str(i))
