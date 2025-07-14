#!/usr/bin/bash
python wazUrDNS.py > >(tee stdout.log) 2> >(tee  stderr.log >&2)

