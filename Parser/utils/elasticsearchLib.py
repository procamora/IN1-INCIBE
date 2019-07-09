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
from elasticsearch import Elasticsearch, exceptions

import functions
import querys_elastic

requests.packages.urllib3.disable_warnings()

TIMEOUT = 60


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

    def addMapping(self, myIndex, fileMapping) -> NoReturn:
        with open(fileMapping, 'r') as fp:
            mapping = fp.read()

        # create an index in elasticsearch, ignore status code 400 (index already exists)
        try:
            self._es.indices.create(index=myIndex, body=mapping)  # , ignore=400)
            self._logger.info(f'Create index {myIndex}')
        except exceptions.RequestError:
            self._logger.error(f"Index: {myIndex} already exists")

    def insert(self, myIndex, file) -> NoReturn:
        with open(file, 'r') as open_file:
            for entry in open_file:
                if len(entry) > 2:  # evitar lineas en blanco "\n"
                    self._es.index(index=myIndex, doc_type=self._doc_type, body=entry)

    def bulk(self, myIndex, file) -> NoReturn:
        contProgress = 0
        incremet = 10000
        count_lines = functions.get_number_lines_file(file, self._logger)

        idElk = 0
        with open(file, 'r') as open_file:
            body = list()
            for entry in open_file:
                if len(entry) > 2:  # evitar lineas en blanco "\n"
                    body.append({'index': {'_id': idElk}})
                    idElk += 1
                    # Intentamos actualizar el campo dangerous y reputation de las descargas si existe en vt
                    entry = self.get_values_pending(entry)
                    body.append(entry)
                    if len(body) > incremet:
                        contProgress += (incremet // 2)
                        self._logger.debug(f'{contProgress}/{count_lines}')
                        response = self._es.bulk(body=body, index=myIndex, doc_type=self._doc_type,
                                                 request_timeout=TIMEOUT)
                        if self.isError(response):
                            self._logger.critical('Exiting...')
                            sys.exit(1)
                        body.clear()
            # Enviamos el resto de datos
            if len(body) != 0:
                self._logger.debug(f'{count_lines}/{count_lines}')
                response = self._es.bulk(body=body, index=myIndex, doc_type=self._doc_type, request_timeout=TIMEOUT)
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
                self._logger.info(f'Dangarous: {positives}')
                t['dangerous'] = positives
                self._logger.debug(entry)

        if 'reputation' in t:
            ip = t['idip'].split(',')[-1]
            if t['reputation'] == -1:  # actualizo aquellos que no se han podido insertar en el parseo
                reputation = functions.malware_analize_reputation_ip(ip)
                if reputation is not None:
                    t['reputation'] = reputation
                    # self._logger.debug(entry)
        return json.dumps(t)

    def malware_analize_shasum(self, shasum) -> Union[Dict[str, str], None]:
        url = f'{self._URL}/analizeHash?hash={shasum}'
        headers = {'Accept': 'application/json'}
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                return json.loads(r.text)['results']['positives']
            return None
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            self._logger.warning("No se ha podido comprobar el hash para %s", shasum)  # fixme traducir
            return None

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
            self._logger.warning(f'Errors found: {len(response["items"])}')
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

        res = self._es.search(body=querys_elastic.json_search_dangerous_unused)
        self._logger.info(f"Got {res['hits']['total']} files")

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
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            self._logger.warning("No se ha podido comprobar la url")  # fixme traducir
            return None

    def create_json_downloads_pending(self) -> NoReturn:
        """
        Metodo que se llama con el metodo update, busca todos los comandos wget y curl que no tienen asociada una
        descarga y crea un json con su informmacion, dangerous y hash se intentan calcular de la bd local, sino se
        tiene almacenada se tendra que obtener despues, despues inserta el json en elastic
        :return:
        """
        self._logger.info('search wget/curl files')

        response = self._es.search(body=querys_elastic.json_search_wgets)
        self._logger.info(f"Got {response['hits']['total']} files")

        # print(json.dumps(response))
        json_insert = list()
        count_lines = len(response['hits']['hits'])
        contProgress = 0
        for hit in response['hits']['hits']:
            self._logger.debug(hit['_source'])
            # print(hit['_source']['input']) # imprime el comando wget

            # Query para buscar si existe un evento de descarga para una determinada sesion con una url especifica
            json_search_downloads = \
                {"query": {
                    "bool": {
                        "must": [
                            {"match": {"eventid": "cowrie.session.file_download"}},
                            {"match": {"session": hit['_source']['session']}},
                            {"match": {"url": hit['_source']['input']}}
                        ]}}}

            responseDownloads = self._es.search(body=json_search_downloads)
            if responseDownloads['hits']['total'] == 0:
                regex = r"((?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:\/?#[\]@!\$&'\(\)\*\+,;=.\%]+)"
                search_url = re.search(regex, hit['_source']['input'])
                if search_url:
                    url = search_url.group(1)
                    entry = self.create_json_donwload(hit['_source']['session'], hit['_source']['timestamp'], url)
                    if entry is not None:
                        functions.writeFile('{}\n'.format(entry), 'downloads.json', 'a')
                        print(entry)
                        self._es.index(index=hit['_index'], doc_type=self._doc_type, body=entry)
                        self._logger.debug('{}/{}'.format(contProgress, count_lines))
                        contProgress += 1

    def create_json_donwload(self, session: str, timestamp: str, url: str) -> Dict[str, str]:
        """
        Metodo para crear un json de tipo descarga dada una url
        Si no se consige saber si la descarga es peligrosa pondremos un -1
        Si no se consigue el hash del fichero en este momento ponemos un -1 pero se intentara obtener posteriormente
        descargandose el fichero
        :param session:
        :param timestamp:
        :param url:
        :return:
        """
        shasum = self.malware_analize_hash_url(url)

        if shasum is None or shasum == '-1':
            self.malware_analize_download_url(url)  # descargamos el fichero, para tenerlo en la siguiente iteracion

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

    def malware_analize_hash_url(self, url) -> Union[str, None]:
        """
        Metodo para preguntar al respositorio de malware si conoce esa url,
        si la conoce retorna su hash
        sino la conoce retorna -1
        si falla al enviar la peticion retorna None (No deberia ocurrir nunca)
        :param url:
        :return:
        """
        data = '{"url": "%s"}' % url
        myjson = json.dumps(json.loads(data))
        url = '{}/getHash'.format(self._URL)
        headers = {'Accept': 'application/json'}
        try:
            r = requests.post(url, data=myjson, headers=headers, timeout=5)
            if r.status_code == 200:
                return json.loads(r.text)['hash']
            return "-1"
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            self._logger.warning("No se ha podido comprobar la reputacion para %s", url)  # fixme traducir
            return None

    def malware_analize_download_url(self, url) -> Union[str, None]:
        """
        Metodo para pedir que se descargue una url
        :param url:
        :return:
        """
        data = '{"url": "%s"}' % url
        myjson = json.dumps(json.loads(data))
        url = '{}/downloadUrl'.format(self._URL)
        headers = {'Accept': 'application/json'}
        try:
            r = requests.post(url, data=myjson, headers=headers, timeout=5)
            if r.status_code == 200:
                return json.loads(r.text)['hash']
            return "-1"
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            self._logger.warning("No se ha podido comprobar la reputacion para %s", url)  # fixme traducir
            return None

    def update_dangerous_downloads_novalid(self):
        res = self._es.search(body=querys_elastic.json_search_url_offline)
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
    logger = functions.getLogger(arg.verbose, 'elk')

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
