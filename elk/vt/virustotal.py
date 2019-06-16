#!/bin/env python3
# -*- coding: utf-8 -*-

import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi

#{"error": "You exceeded the public API request rate limit (4 requests of any nature per minute)", "response_code": 204}

VIRUSTOTAL_API_KEY = "67252f63c647a289f89c46900ab6d45092f243a8229b21caac848a99b7a3a219"

def analizeHash(nhash):
    vt = VirusTotalPublicApi(VIRUSTOTAL_API_KEY)
    response = vt.get_file_report(nhash)
    return json.dumps(response, sort_keys=False)
    #return json.dumps(response, sort_keys=False, indent=4)


def analizeUrl(url):
    vt = VirusTotalPublicApi(VIRUSTOTAL_API_KEY)
    response = vt.scan_url(url)
    return json.dumps(response, sort_keys=False)


if __name__ == "__main__":
    EICAR = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".encode('utf-8')
    EICAR_MD5 = hashlib.md5(EICAR).hexdigest()
    #print(EICAR_MD5)
    #print(analizeHash(EICAR_MD5))
    print(analizeHash("18081a9d70111fd849150b4d529eef3c"))

    URL_DOWNLOAD = "http://121.174.70.181/zehir/z3hir.sh4"
    print(analizeUrl(URL_DOWNLOAD))
