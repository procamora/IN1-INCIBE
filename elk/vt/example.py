#!/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import sys


URL = "http://127.0.0.1:8080"


#https://urlhaus.abuse.ch/browse/
#URL_DOWNLOAD = "https://pypi.org/static/images/logo-small.6eef541e.svg" 
URL_DOWNLOAD = "http://121.174.70.181/zehir/z3hir.sh4" 
URL_DOWNLOAD = "https://miro.medium.com/max/790/1*uHzooF1EtgcKn9_XiSST4w.png" 


def download():
	data = '''{"url": "%s"}''' %(URL_DOWNLOAD)

	myjson = json.dumps(json.loads(data))

	url = '{}/download'.format(URL)
	headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
	r = requests.post(url, data=myjson, headers=headers)

	print("download:", r.status_code)
	print(r.text)
	print('')


def url():
	data = '''{"url": "%s"}''' %(URL_DOWNLOAD)

	myjson = json.dumps(json.loads(data))

	url = '{}/analize'.format(URL)
	headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
	r = requests.post(url, data=myjson, headers=headers)

	print("download:", r.status_code)
	print(r.text)
	print('')


def md5(md5hex):
	url = '{}/analize?md5={}'.format(URL, md5hex)
	headers = {'Accept': 'application/json'}
	r = requests.get(url, headers=headers)

	print("md5:", r.status_code)
	print(r.text)
	print('')


list_hash = ('d1bdc5aaa294b4c52678c4c60f052569', '087951566fb77fe74909d4e4828dd4cb', 
	'8aacf26df235661245e98cb60e820f51', 'be0d32bb3a12896ff16e3f667eb4b644', 
	'f388391ca443056fd3b4cc733c3b61cd', '344324e74971148b2b537e35511cacba', 
	'd6113972a2173a5f81da9d37cc43bbaa', 'f96980293893c2b1f5da2d634a7e2a06', 
	'0a60424e0967b6cfc172dac82e10a2fe', '13f998379288f3c92c0d6cda66c701bc', 
	'76a2f2ce03df87d87a45ab7890808a40', '66f534535b1647618f805f2aaca84fce', 
	'2d9a3315b9ff59d1db0b7cc4624a2c87', 'fca4501c008103081a7ec43e455678ff', 
	'f603ff7e25027ff6892118ab3ce2c07c', '978a0e667f0aea05984b4b746b3c42c8', 
	'51a057635fd5d481dd9dd6f0dc316370', '705647da49085cd19ac9a74715a36f38')

for i in list_hash:
	print(i)
	md5(i)




#url()
md5("815f40789226a46453943b3fe7ad1eaf")
#download()