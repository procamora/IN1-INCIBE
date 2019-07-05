#!/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import json
import re
import sys
from timeit import default_timer as timer
from typing import NoReturn, Dict, Any, Union

import requests
from elasticsearch import Elasticsearch

requests.packages.urllib3.disable_warnings()

from functions import getLogger, get_shasum, writeFile


class Elastic(object):
    def __init__(self, ip, logger) -> None:
        self._es = Elasticsearch(
            [ip],
            # http_auth=('user', 'secret'),
            # scheme="http",
            verify_certs=True
        )

        if not self._es.ping():
            raise ValueError("Connection failed, Exiting!!")

        self._logger = logger
        self._doc_type = 'object'  # object y nested
        self._URL = "http://127.0.0.1:8080"

    def addMapping(self, myIndex, fileMapping) -> NoReturn:
        with open(fileMapping, 'r') as fp:
            mapping = fp.read()

        # create an index in elasticsearch, ignore status code 400 (index already exists)
        try:
            self._es.indices.create(index=myIndex, body=mapping)  # , ignore=400)
        except:
            self._logger.error("Index: {} already exists".format(myIndex))
        self._logger.info('Create index {}'.format(myIndex))

    def insert(self, myIndex, file) -> NoReturn:
        with open(file, 'r') as open_file:
            for entry in open_file:
                if len(entry) > 2:  # evitar lineas en blanco "\n"
                    self._es.index(index=myIndex, doc_type=self._doc_type, body=entry)
        # print('index: ' + res['result'])
        # but not deserialized
        # res = self._es.get(index=myIndex, doc_type=self._doc_type)
        # print('get: ' + str(res['_source']))
        # self._es.indices.refresh(index=myIndex)

    def bulk(self, myIndex, file) -> NoReturn:
        contProgress = 0
        incremet = 10000
        with open(file, 'r') as fp:
            count_lines = len(fp.readlines())

        idElk = 0
        with open(file, 'r') as open_file:
            body = list()
            for entry in open_file:
                if len(entry) > 2:  # evitar lineas en blanco "\n"
                    body.append({'index': {'_id': idElk}})
                    idElk += 1
                    # Intentamos actualizar el campo dangerous de las descargas si existe en vt
                    entry = self.get_values_pending(entry)
                    body.append(entry)
                    if len(body) > incremet:
                        contProgress += (incremet // 2)
                        self._logger.debug('{}/{}'.format(contProgress, count_lines))
                        response = self._es.bulk(body, index=myIndex, doc_type=self._doc_type)
                        if self.isError(response):
                            self._logger.critical('Exiting...')
                            sys.exit(1)
                        body.clear()
            # Enviamos el resto de datos
            if len(body) != 0:
                self._logger.debug('{}/{}'.format(count_lines, count_lines))
                response = self._es.bulk(body, index=myIndex, doc_type=self._doc_type)
                if self.isError(response):
                    self._logger.critical('Exiting...')
                    sys.exit(1)

    def get_values_pending(self, entry) -> Dict[str, Any]:
        """
        Metodo para actualizar el valor dangerous preguntando por el hash del fichero y la reputacion de la ip

        :param entry:
        :return:
        """
        t = json.loads(entry)
        if 'dangerous' in t:
            self._logger.info(t)
            positives = self.malware_analize_shasum(t['shasum'])
            if positives is not None:
                self._logger.info('Dangarous: {}'.format(positives))
                t['dangerous'] = positives
                self._logger.debug(entry)
        if 'reputation' in t:
            ip = t['idip'].split(',')[-1]
            t['reputation'] = self.get_reputation_ip(ip)
        return json.dumps(t)

    def isError(self, response) -> bool:
        """
        Metodo que comrpueba si la respuesta de bulk o insert es correcta, en caso de que no sea correcta muestra
        algunos de los errores y despues informa para finalizar la ejecucion del programa

        :param response:
        :return:
        """

        maxErrors = 20
        actualErros = 0
        if response['errors']:
            self._logger.warning('Errors found: {}'.format(len(response['items'])))
            for i in response['items']:
                if i['index']['status'] == 400:
                    self._logger.debug(response['errors'])
                    self._logger.debug(i)
                    self._logger.warning(i['index']['error'])
                    actualErros += 1
                    if actualErros == maxErrors:
                        return True

        if actualErros != 0:
            return True
        return False

    def update_dangerous_files(self) -> NoReturn:
        self._logger.info('Update downloaded files')
        jsonSearch = \
            {
                "size": 10000,
                "query": {
                    "term": {"dangerous": -1}
                }
            }
        res = self._es.search(body=jsonSearch)
        self._logger.info("Got {} files".format(res['hits']['total']))

        for hit in res['hits']['hits']:
            self._logger.debug(hit['_source'])
            positives = self.malware_analize_url(hit['_source']['url'])
            if positives is not None:
                jsonUpdate = \
                    {
                        "doc": {
                            "dangerous": positives
                        }
                    }
                self._es.update(index=hit['_index'], doc_type=hit['_type'], id=hit['_id'], body=jsonUpdate)

    def malware_analize_url(self, url_analize) -> Union[Dict[str, str], None]:
        data = '{"url": "%s"}' % url_analize
        myjson = json.dumps(json.loads(data))
        url = '{}/analize'.format(self._URL)
        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

        try:
            r = requests.post(url, data=myjson, headers=headers, timeout=5)
            if r.status_code == 200:
                return json.loads(r.text)['results']['positives']
            return None
        except requests.exceptions.ConnectionError:
            self._logger.warning("No se ha podido comprobar la url")  # fixme traducir
            return None

    def update_json_downloads(self) -> NoReturn:
        """
        Metodo que se llama con el metodo update, busca todos los comandos wget y curl que no tienen asociada una
        descarga y descargan ese fichero, calcula el hash e inserta ese dato en elasticsearch
        :return:
        """
        self._logger.info('search wget/curl files')
        jsonSearchWgets = \
            {
                "size": 10000,
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"binary": "wget"}},
                            {"term": {"binary": "curl"}}
                        ]
                    }
                }
            }

        response = self._es.search(body=jsonSearchWgets)
        self._logger.info("Got {} files".format(response['hits']['total']))

        # print(json.dumps(response))
        json_insert = list()
        count_lines = len(response['hits']['hits'])
        contProgress = 0
        for hit in response['hits']['hits']:
            self._logger.debug(hit['_source'])
            # print(hit['_source']['input']) # imprime el comando wget
            jsonSearchDownloads = \
                {
                    "query": {
                        "bool": {
                            "must": [
                                {"match": {"eventid": "cowrie.session.file_download"}},
                                {"match": {"session": hit['_source']['session']}},
                                {"match": {"url": hit['_source']['input']}}
                            ]
                        }
                    }
                }
            responseDownloads = self._es.search(body=jsonSearchDownloads)
            if responseDownloads['hits']['total'] == 0:
                regex = r"((?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:\/?#[\]@!\$&'\(\)\*\+,;=.\%]+)"
                search_url = re.search(regex, hit['_source']['input'])
                if search_url:
                    url = search_url.group(1)
                    entry = self.create_json_donwload(hit['_source']['session'], hit['_source']['timestamp'], url)
                    if entry is not None:
                        writeFile('{}\n'.format(entry), 'downloads.json', 'a')
                        print(entry)
                        self._es.index(index=hit['_index'], doc_type=self._doc_type, body=entry)
                        self._logger.debug('{}/{}'.format(contProgress, count_lines))
                        contProgress += 1

    def create_json_donwload(self, session: str, timestamp: str, url: str) -> Dict[str, str]:
        shasum = get_shasum(url)
        if shasum is None:
            self._logger.warning('Can not be downloaded {}'.format(url))
            json_table = {'session': session, 'timestamp': timestamp, 'url': url, 'outfile': "-1", 'shasum': "-1",
                          'dangerous': -2, 'eventid': 'cowrie.session.file_download'}
            return json.dumps(json_table)
        outfile = 'var/lib/cowrie/downloads/{}'.format(shasum)

        positives = self.malware_analize_shasum(shasum)
        if positives is not None:
            dangerous = positives
        else:
            dangerous = -1
        json_table = {'session': session, 'timestamp': timestamp, 'url': url, 'outfile': outfile, 'shasum': shasum,
                      'dangerous': dangerous, 'eventid': 'cowrie.session.file_download'}
        return json.dumps(json_table)

    def malware_analize_shasum(self, shasum) -> Union[Dict[str, str], None]:
        url = '{}/analize?md5={}'.format(self._URL, shasum)
        headers = {'Accept': 'application/json'}
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                return json.loads(r.text)['results']['positives']
            return None
        except requests.exceptions.ConnectionError:
            self._logger.warning("No se ha podido comprobar el hash")  # fixme traducir
            return None

    def update_dangerous_downloads_novalid(self):
        query_selecct = \
            {
                "size": 10000,
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"eventid": "cowrie.session.file_download"}},
                            {"match": {"shasum.keyword": "-1"}},
                            {"match": {"outfile.keyword": "-1"}}
                        ]
                    }
                }
            }
        res = self._es.search(body=query_selecct)
        self._logger.info("Gots {} files".format(res['hits']['total']))
        for hit in res['hits']['hits']:
            self._logger.debug(hit['_source'])
            jsonUpdate = \
                {
                    "doc": {
                        "dangerous": -2
                    }
                }
            self._es.update(index=hit['_index'], doc_type=hit['_type'], id=hit['_id'], body=jsonUpdate)

    def get_reputation_ip(self, ip) -> int:
        req_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0'}
        response = requests.get('https://threatwar.com/ip/{}'.format(ip), headers=req_headers, verify=False)

        if response.status_code == 200:
            regex = r'<td>Total Attacks<\/td>( )*(\n)?( )*<td>(\d+)<\/td>'
            if re.search(regex, response.text):
                reputation = int(re.search(regex, response.text).group(4))
                self._logger.debug('reputation ip {}: {}'.format(ip, reputation))
                return reputation  # reputacion de la ip
            return -1  # ip no se ha podido analizar
        return -2  # ip no se encuentra


def CreateArgParser() -> argparse:
    """
    Metodo para establecer los argumentos que necesita la clase

    :return:
    """
    config = configparser.ConfigParser()
    config.sections()
    config.read('../settings.conf')

    example = 'python3 %(prog)s -f ../output/cowrie.completed.json -ip "127.0.0.1:9200" -i cowrie-s2 ' \
              '-m mapping.json -v'
    myParser = argparse.ArgumentParser(description='%(prog)s is a script to enter data in the elasticsearch database.',
                                       usage='{}'.format(example))

    myParser.add_argument('-f', '--file', help='File to upload.')
    myParser.add_argument('-m', '--mapping', help='Path of the file where the mapping of the attributes is defined.')
    myParser.add_argument('-ip', '--ip', help='IP address of the server where ElasticSearch is located.')
    myParser.add_argument('-i', '--index', help='Name of the index.')
    myParser.add_argument('-b', '--bulk', action='store_true', help='bulk mode (boolean).', default=True)
    myParser.add_argument('-u', '--update', action='store_true', help='update dangerous files (boolean).',
                          default=False)
    myParser.add_argument('-v', '--verbose', action='store_true', help='Verbose flag (boolean).', default=False)

    # tambien lo puedo poner en la misma linea
    myParser.set_defaults(ip=config['DEFAULTS']['ELASTIC_IP'])
    myParser.set_defaults(index=config['DEFAULTS']['ELASTIC_INDEX'])
    # myParser.print_help()
    return myParser.parse_args()


if __name__ == '__main__':
    startTotal = timer()

    arg = CreateArgParser()
    logger = getLogger(arg.verbose, 'elk')

    e = Elastic(arg.ip, logger)

    if arg.mapping is not None:
        e.addMapping(arg.index, arg.mapping)

    if arg.update:
        e.update_dangerous_downloads_novalid()
        # e.updateDangerousFiles()
        # e.update_json_downloads()
    else:
        if arg.file is None:
            logger.critical("The following arguments are required: -f/--file")
            sys.exit(1)

        if arg.bulk:
            e.bulk(arg.index, arg.file)
        else:
            e.insert(arg.index, arg.file)

    endTotal = timer()
    logger.debug('Tiempo total: {} seg'.format(endTotal - startTotal))  # Time in seconds, e.g. 5.38
