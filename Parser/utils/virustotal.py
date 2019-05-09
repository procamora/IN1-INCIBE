#!/bin/env python3
# -*- coding: utf-8 -*-


import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import configparser

config = configparser.ConfigParser()
config.sections()
config.read('../settings.conf')

EICAR = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".encode('utf-8')
EICAR_MD5 = hashlib.md5(EICAR).hexdigest()


print(config['DEFAULTS']['VIRUSTOTAL_API_KEY'])


vt = VirusTotalPublicApi(config['DEFAULTS']['VIRUSTOTAL_API_KEY'])

response = vt.get_file_report(EICAR_MD5)
print(json.dumps(response, sort_keys=False, indent=4))