# !/bin/env python3
# -*- coding: utf-8 -*-

import json
from http import HTTPStatus  # https://docs.python.org/3/library/http.html
from timeit import default_timer as timer
from typing import NoReturn, Dict, Union

import requests
from elasticsearch import Elasticsearch

import functions

TIMEOUT = 600


def _malware_download_url(url_download: str) -> Union[str, None]:
    """
    Metodo para pedir que se descargue una url
    :param url_download:
    :return:
    """
    _URL = "http://127.0.0.1:8080"
    url = f'{_URL}/downloadUrl'
    data = '{"url": "%s"}' % url_download
    myjson = json.dumps(json.loads(data))
    headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
    try:
        r = requests.post(url, data=myjson, headers=headers)
        if r.status_code == HTTPStatus.PARTIAL_CONTENT:  # descarga en proceso
            return None

        resp = json.loads(r.text)
        try:
            if 'error' in resp.keys():
                return None
            elif r.status_code == HTTPStatus.OK and resp['results']['response_code'] == 1:
                # print(resp)
                return resp['results']['positives']
            return "-1"
        except KeyError:
            return None
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        print("No se ha podido descargar para %s", url_download)  # fixme traducir
        return None


class Elastic(object):
    def __init__(self, ip, logger) -> None:
        self._es = Elasticsearch(
            [ip],
            # http_auth=('user', 'secret'),
            # scheme="http",
            timeout=TIMEOUT, max_retries=10, retry_on_timeout=True,
            verify_certs=True
        )

        self._es.cluster.health(wait_for_status='yellow', request_timeout=TIMEOUT)

        if not self._es.ping():
            raise ValueError("Connection failed, Exiting!!")

        self._logger = logger
        self._doc_type = 'object'  # object y nested
        self._URL = "http://127.0.0.1:8080"

    def process_hits_update_dangerous_files(self, hits: Dict) -> NoReturn:
        self._logger.info(f"Got {len(hits)} files")
        for hit in hits:
            self._logger.info(f"Got {hit['_source']['url']}")
            _malware_download_url(hit['_source']['url'])

    def update_dangerous_files(self) -> NoReturn:
        """
        Metodo que se ejecuta en el segundo paso, busca todos las descargas que tengan un -1 he intenta actualizar a su
        valor real
        :return:
        """
        self._logger.info('Step 2: Update downloaded files')

        json_search_wgets = \
            {
                "size": 1000,
                "query": {
                    "term": {"eventid": "cowrie.session.file_download"}
                }
            }
        response = self._es.search(body=json_search_wgets, scroll='2m')

        # fuente https://gist.github.com/hmldd/44d12d3a61a8d8077a3091c4ff7b9307
        # Get the scroll ID
        sid = response['_scroll_id']
        scroll_size = len(response['hits']['hits'])
        # Before scroll, process current batch of hits
        self.process_hits_update_dangerous_files(response['hits']['hits'])

        while scroll_size > 0:
            "Scrolling..."
            response = self._es.scroll(scroll_id=sid, scroll='2m')
            # Process current batch of hits
            self.process_hits_update_dangerous_files(response['hits']['hits'])
            # Update the scroll ID
            sid = response['_scroll_id']
            # Get the number of results that returned in the last scroll
            scroll_size = len(response['hits']['hits'])


if __name__ == '__main__':
    startTotal = timer()

    logger = functions.get_logger(True, 'elk')
    e = Elastic("127.0.0.1", logger)
    e.update_dangerous_files()

    endTotal = timer()
    logger.debug('Tiempo total: {} seg'.format(endTotal - startTotal))  # Time in seconds, e.g. 5.38
