#!/usr/bin/python
import requests
import urllib.parse
import csv
from publicsuffixes import publicsuffixes
from io import StringIO

def is_public_suffix(domainname):
    if domainname == "": 
        return True
    assert(domainname[-1] == ".")
    d=domainname[:-1].lower()
    for p in publicsuffixes:
        if p.startswith('*'):
            if d == p[2:] or d.endswith(p[1:]):
                #print(f"wildcard match {p=} {d=}")
                return True
        else:
            if d == p:
                #print(f"match {p=} {d=}")
                return True
    return False

assert(is_public_suffix("DE.") == True)
assert(is_public_suffix("exAmple.de.") == False)
assert(is_public_suffix("something.zerops.app.") == True)
assert(is_public_suffix("zerops.app.") == True)
assert(is_public_suffix("abc.def.egh.zerops.app.") == True)

def get_subdomains(domainname,include_self=True):
    ret = []
    domainname = domainname.lower()
    if not include_self:
        domainname = ".".join(domainname.split(".")[1:])
    while not is_public_suffix(domainname):
        ret.append(domainname)
        domainname = ".".join(domainname.split(".")[1:])
    return ret

assert(get_subdomains("abc.www.test.de.") == ["abc.www.test.de.","www.test.de.","test.de."])
assert(get_subdomains("test.co.uk.") == ["test.co.uk."])
assert(get_subdomains("abc.www.test.de.",include_self=False) == ["www.test.de.","test.de."])
assert(get_subdomains("test.co.uk.",include_self=False) == [])

def get_sublabels(domainname, ignore_depth=1):
    ret = []
    domainname = domainname.lower()
    while not is_public_suffix(domainname):
        ret.append(domainname.split(".")[0])
        domainname = ".".join(domainname.split(".")[1:])
    if ignore_depth > 0: ret=ret[:-ignore_depth]
    return sorted(list(set(ret)))

assert(get_sublabels("www.test.de.") == ["www"])
assert(get_sublabels("www.abc.test.co.uk.") == ["abc", "www"])
assert(get_sublabels("www.test.de.", ignore_depth=2) == [])
assert(get_sublabels("www.abc.test.co.uk.", ignore_depth=2) == ["www"])
assert(get_sublabels("www.test.de.", ignore_depth=0) == ["test", "www"])
assert(get_sublabels("www.abc.test.co.uk.", ignore_depth=0) == ["abc", "test", "www"])

def get_main_domain(domainname):
    ret = get_subdomains(domainname)
    if len(ret) > 0:
        return ret[-1]
    else:
        assert("domainname should not be a public one!" == False)


def certificate_transparency_lookup(maindomain):
    url = "https://crt.sh/csv?q="+ urllib.parse.quote_plus(maindomain[:-1])
    r=requests.get(url).content
    r=r.decode('utf-8')
    class MyDialect(csv.Dialect):
        delimiter      = ','
        doublequote    = False 
        lineterminator = '\n'
        quotechar      = '"'
        quoting        = csv.QUOTE_MINIMAL
    c=[i for i in csv.DictReader(StringIO(r), dialect=MyDialect)]
    try:
        d=[i["Common Name"] for i in c]
        for i in c:
            d += i["Matching Identities"].split('\n')
        d = [i+"." for i in d if i != ""]
        # remove wildcards
        d = [i[2:] if i.startswith("*.") else i for i in d]
        # remove emails (just keep domain part
        d = [i.split('@')[-1] for i in d]
        return sorted(list(set(d)))
    except:
        #print(r)
        #print(maindomain)
        return []
#assert(certificate_transparency_lookup("hohenpoelz.de.") == ['blaskapelle.hohenpoelz.de', 'blaskapellehohenpoelz.de', 'hohenpoelz.de', 'klaus.hohenpoelz.de', 'mta-sts.hohenpoelz.de', 'nr47.hohenpoelz.de', 'www.blaskapellehohenpoelz.de'])
