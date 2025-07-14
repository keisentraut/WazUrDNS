# WazUrDNS

This is a DNS enumeration tool.
You provide a list of IPs, a list of already known DNS names and it will do the rest fully automatically.

For instance, it can look like the following, if you provide only a single IP or DNS name:

- The reverse lookup for the initially given IP finds ```www.example.com```.
- From there, the script will try common prefixes and identify ```vpn01.example.com```, too.
- It will do a certificate transparency lookup for ```example.com```, too and find other hostnames such as ```blog.example.com```.
- It will detect ```vpn02.example.com```, too, as it already knows ```vpn01.example.com``` and this is a common modification.

*Caution*: Some settings (especially the NS and the "add-new-ips" feature) are very aggressive and you have a very high chance that you will include the whole internet or some large cloud providers.
It is highly recommended to use a maximum depth if you enable those features.

## Features


- crt.sh lookup for certificate transparency
- prefix brute-forcing
- different types of lookups: A, AAAA, NS, MX, TXT, CNAME, PTR (reverse hostname)
- automatic DNS wildcard detection
- google dorking

### missing features

- MX parsing
- SPF parsing
- DNSSEC NSEC zone walking
- DNSSEC NSEC3 hash cracking 
- scan resumption
- HTTP(S) crawling and parsing HTML content for new domain names

## Usage

Typically, you want to do

- modify 
  - ```prefixes.txt```: DNS labels to brute-foce, e.g. ```www```
  - ```ips.txt```: List of initial IPv4/IPv6
  - ```blacklist.txt```: domains which it should ignore, e.g. Amazon/Cloudflare/... subdomains
- change the global ```CONF``` variable in ```wazUrDNS.py```, for instance, add more resolvers or increase speed
- run ```python wazUrDNS.py | > >(tee -a stdout.log) 2> >(tee -a stderr.log >&2)``` to save and see the output
- The script needs occasional supervision to ensure that it the queue gets actually smaller and not exponentionally larger. If this happens, then adapt settings or blacklist if necessary if it does scan too aggressive and gets stuck.
- look into ```stdout.log``` to get the final list of results

## Example results

If it is just given my VPS IP ```37.120.174.168```, then it finds the following list of results:

```
hohenpoelz.de. A 37.120.174.168
hohenpoelz.de. AAAA 2a03:4000:6:7598::1
hohenpoelz.de. CERTTRANS blaskapelle.hohenpoelz.de.
hohenpoelz.de. CERTTRANS blaskapellehohenpoelz.de.
hohenpoelz.de. CERTTRANS hohenpoelz.de.
hohenpoelz.de. CERTTRANS klaus.hohenpoelz.de.
hohenpoelz.de. CERTTRANS mta-sts.hohenpoelz.de.
hohenpoelz.de. CERTTRANS nr47.hohenpoelz.de.
hohenpoelz.de. CERTTRANS www.blaskapellehohenpoelz.de.
hohenpoelz.de. MX 0 hohenpoelz.de.
hohenpoelz.de. TXT "v=spf1 mx -all"
blaskapellehohenpoelz.de. CERTTRANS blaskapellehohenpoelz.de.
blaskapellehohenpoelz.de. CERTTRANS mail.comune.blaskapellehohenpoelz.de.
blaskapellehohenpoelz.de. CERTTRANS www.blaskapellehohenpoelz.de.
```

## FAQ 

### What is the difference to dnsrecon?

This is a more "automated" and "recursive" approach, but not all features of dnsrecon are currently implemented (but e.g. dnsrecon does not do certificate lookup either).
This tool is intended for penetration testing / red teaming where you do not want to spend more time on manual DNS reconaissance then necessary.
