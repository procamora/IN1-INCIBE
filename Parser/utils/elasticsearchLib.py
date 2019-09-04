#!/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import json
import logging
import re
import sys
from http import HTTPStatus  # https://docs.python.org/3/library/http.html
from timeit import default_timer as timer
from typing import NoReturn, Dict, Any, Union

import requests
from elasticsearch import Elasticsearch, exceptions

import functions
import querys_elastic

requests.packages.urllib3.disable_warnings()

TIMEOUT = 600


class Elastic(object):
    def __init__(self, ip: str, logger: logging) -> None:
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

    def create_mapping(self, my_index, file_mapping) -> NoReturn:
        with open(file_mapping, 'r') as fp:
            mapping = fp.read()

        # create an index in elasticsearch, ignore status code 400 (index already exists)
        try:
            self._es.indices.create(index=my_index, body=mapping)  # , ignore=400)
            self._logger.info(f'Create index {my_index}')
        except exceptions.RequestError:
            self._logger.error(f"Index: {my_index} already exists")

    def insert(self, my_index, file) -> NoReturn:
        with open(file, 'r') as open_file:
            for entry in open_file:
                if len(entry) > 2:  # evitar lineas en blanco "\n"
                    self._es.index(index=my_index, doc_type=self._doc_type, body=entry)

    def bulk(self, my_index, file) -> NoReturn:
        cont_progress = 0
        incremet = 10000
        count_lines = functions.get_number_lines_file(file, self._logger)

        id_elk = 0
        with open(file, 'r') as open_file:
            body = list()
            for entry in open_file:
                if len(entry) > 2:  # evitar lineas en blanco "\n"
                    body.append({'index': {'_id': id_elk}})
                    id_elk += 1
                    # Intentamos actualizar el campo dangerous y reputation de las descargas si existe en vt
                    entry = self._get_values_pending(entry)
                    body.append(entry)
                    if len(body) > incremet:
                        cont_progress += (incremet // 2)
                        self._logger.debug(f'{cont_progress}/{count_lines}')
                        response = self._es.bulk(body=body, index=my_index, doc_type=self._doc_type,
                                                 request_timeout=TIMEOUT)
                        if self._is_error(response):
                            self._logger.critical('Exiting...')
                            sys.exit(1)
                        body.clear()
            # Enviamos el resto de datos
            if len(body) != 0:
                self._logger.debug(f'{count_lines}/{count_lines}')
                response = self._es.bulk(body=body, index=my_index, doc_type=self._doc_type, request_timeout=TIMEOUT)
                if self._is_error(response):
                    self._logger.critical('Exiting...')
                    sys.exit(1)

    def _get_values_pending(self, entry) -> Dict[str, Any]:
        """
        Metodo para actualizar el valor dangerous preguntando por el hash del fichero y la reputacion de la ip

        :param entry:
        :return:
        """
        t = json.loads(entry)
        if 'dangerous' in t:
            self._logger.info(t)
            positives = self._malware_analize_shasum(t['shasum'])
            if positives is not None:
                self._logger.info(f'Dangarous: {positives}')
                t['dangerous'] = positives
                self._logger.debug(entry)

        if 'reputation' in t:
            ip = t['idip'].split(',')[-1]
            if t['reputation'] == -1:  # actualizo aquellos que no se han podido insertar en el parseo
                reputation = functions.malware_get_reputation_ip(ip, self._logger)
                if reputation is not None:
                    t['reputation'] = reputation
                    # self._logger.debug(entry)
        return json.dumps(t)

    def _is_error(self, response) -> bool:
        """
        Metodo que comrpueba si la respuesta de bulk o insert es correcta, en caso de que no sea correcta muestra
        algunos de los errores y despues informa para finalizar la ejecucion del programa

        :param response:
        :return:
        """

        max_errors = 20
        actual_errors = 0
        if response['errors']:
            self._logger.warning(f'Errors found: {len(response["items"])}')
            for i in response['items']:
                if i['index']['status'] == 400:
                    self._logger.debug(response['errors'])
                    self._logger.debug(i)
                    self._logger.warning(i['index']['error'])
                    actual_errors += 1
                    if actual_errors == max_errors:
                        return True

        if actual_errors != 0:
            return True
        return False

    def process_hits_update_dangerous_files(self, hits: Dict):
        self._logger.info(f"Got {len(hits)} files")
        for hit in hits:
            # self._logger.info(hit['_source']['url'])
            positives = self._malware_analize_url(hit['_source']['url'])
            if positives is not None:
                self._logger.debug(f"Dangerous {positives} for {hit['_source']['url']}")
                json_update = \
                    {
                        "doc": {
                            "dangerous": positives
                        }
                    }
                self._es.update(index=hit['_index'], doc_type=hit['_type'], id=hit['_id'], body=json_update)

    def update_dangerous_files(self) -> NoReturn:
        """
        Metodo que se ejecuta en el segundo paso, busca todos las descargas que tengan un -1 he intenta actualizar a su
        valor real
        :return:
        """
        self._logger.info('Step 2: Update downloaded files')

        response = self._es.search(body=querys_elastic.json_search_dangerous_unused, scroll='2m')

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

    def process_hits_json_downloads_pending(self, hits: Dict, just_download: bool):
        """
        Metodo que para cada bloque de 1000 conexiones comprueba si cada una de los comandos wget tiene asociaco una
        descarga
        :param hits:
        :param just_download:
        :return:
        """

        count_lines = len(hits)
        count_progress = 1
        self._logger.info(f"Got {len(hits)} files")
        for hit in hits:
            self._logger.debug(f'{count_progress}/{count_lines}')
            count_progress += 1
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

            response_downloads = self._es.search(index=hit['_index'], body=json_search_downloads)
            # si no existe descarga asociada la creamos y la subimos
            if response_downloads['hits']['total'] == 0:
                # self._logger.debug(hit['_source'])
                # regex = r"((?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:\/?#[\]@!\$&'\(\)\*\+,;=.\%]+)"
                # fixme pongo obligatorio el http para encontrar la url, fallara???
                regex = r"((?:http(s):\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:\/?#[\]@!\$&'\(\)\*\+,;=.\%]+)"
                search_url = re.search(regex, hit['_source']['input'])
                if search_url:
                    url = search_url.group(1)
                    entry = self._create_json_donwload(hit['_source']['session'], hit['_source']['timestamp'], url,
                                                       just_download)
                    if entry is not None:
                        # functions.write_file('{}\n'.format(entry), 'downloads.json', 'a')
                        print(entry)
                        self._es.index(index=hit['_index'], doc_type=self._doc_type, body=entry)

    def create_json_downloads_pending(self, just_download: bool) -> NoReturn:
        """
        Metodo que se llama con el metodo update, busca todos los comandos wget y curl que no tienen asociada una
        descarga y crea un json con su informmacion, dangerous y hash se intentan calcular de la bd local, sino se
        tiene almacenada se tendra que obtener despues, despues inserta el json en elastic
        :return:
        """
        if just_download:
            self._logger.info('Step 1.1: search wget/curl files and download')
        else:
            self._logger.info('Step 1.2: search wget/curl files and analize')

        response = self._es.search(body=querys_elastic.json_search_wgets, scroll='2m')

        # fuente https://gist.github.com/hmldd/44d12d3a61a8d8077a3091c4ff7b9307
        # Get the scroll ID
        sid = response['_scroll_id']
        scroll_size = len(response['hits']['hits'])
        # Before scroll, process current batch of hits
        self.process_hits_json_downloads_pending(response['hits']['hits'], just_download)

        while scroll_size > 0:
            "Scrolling..."
            response = self._es.scroll(scroll_id=sid, scroll='2m')
            # Process current batch of hits
            self.process_hits_json_downloads_pending(response['hits']['hits'], just_download)
            # Update the scroll ID
            sid = response['_scroll_id']
            # Get the number of results that returned in the last scroll
            scroll_size = len(response['hits']['hits'])

    def _create_json_donwload(self, session: str, timestamp: str, url: str, just_download: bool) \
            -> Union[Dict[str, str], None]:
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

        # primera iteracion pide que descargue todos lso ficheros unicamente para tenerlos en la siguiente interacion
        if just_download:
            self._malware_download_url(url)
            return None

        # intentamos obtener el hash de la url si esta ya en la bd local
        shasum = self._malware_get_hash_url(url)

        # sino tenemos el hash es que esta offline, porque en la primera interacion le pedimos que lo descargara
        if shasum is None or shasum == '-1':
            self._logger.warning('Can not be downloaded {}'.format(url))
            json_table = {'session': session, 'timestamp': timestamp, 'url': url, 'outfile': "-1", 'shasum': "-1",
                          'dangerous': -2, 'eventid': 'cowrie.session.file_download'}
            return json.dumps(json_table)

        outfile = 'var/lib/cowrie/downloads/{}'.format(shasum)
        positives = self._malware_analize_shasum(shasum)
        if positives is not None:
            dangerous = positives
        else:
            dangerous = -1
        json_table = {'session': session, 'timestamp': timestamp, 'url': url, 'outfile': outfile, 'shasum': shasum,
                      'dangerous': dangerous, 'eventid': 'cowrie.session.file_download'}
        return json.dumps(json_table)

    def _malware_analize_shasum(self, shasum: str) -> Union[Dict[str, str], None]:
        """
        Metodo para preguntar al repositorio de malware por la peligrosidad de un hash
        :param shasum:
        :return:
        """
        if shasum == '-1':
            return None

        url = f'{self._URL}/analizeHash?hash={shasum}'
        print(url)
        headers = {'Accept': 'application/json'}
        try:
            r = requests.get(url, headers=headers)
            resp = json.loads(r.text)
            if len(resp) <= 2:  # fichero offline pero almacenado en la bd
                return None
            elif 'error' in resp.keys():
                return None
            self._logger.warning(resp)
            if r.status_code == HTTPStatus.OK and resp['results']['response_code'] == 1:
                return resp['results']['positives']
            return None
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            self._logger.warning("No se ha podido comprobar el hash para %s", shasum)  # fixme traducir
            return None

    def _malware_analize_url(self, url_analize: str) -> Union[int, None]:
        """
        Metodo para preguntar al repositorio de malware por la peligrosidad de una url
        :param url_analize:
        :return:
        """
        url = f'{self._URL}/analizeUrl'
        data = '{"url": "%s"}' % url_analize
        myjson = json.dumps(json.loads(data))
        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

        try:
            r = requests.post(url, data=myjson, headers=headers)
            resp = json.loads(r.text)
            return Elastic.get_dangerous_json(resp, r.status_code)
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            self._logger.warning("No se ha podido comprobar la url")  # fixme traducir
            return None

    def _malware_download_url(self, url_download: str) -> Union[str, None]:
        """
        Metodo para pedir que se descargue una url
        :param url_download:
        :return:
        """
        url = f'{self._URL}/downloadUrl'
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
                    print(resp)
                    return resp['results']['positives']
                return "-1"
            except KeyError:
                return None
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            self._logger.warning("No se ha podido descargar para %s", url_download)  # fixme traducir
            return None

    def _malware_get_hash_url(self, url_download) -> Union[str, None]:
        """
        Metodo para preguntar al respositorio de malware si conoce esa url,
        si la conoce retorna su hash
        sino la conoce retorna -1
        si falla al enviar la peticion retorna None (No deberia ocurrir nunca)
        :param url_download:
        :return:
        """
        url = f'{self._URL}/getHash'
        data = '{"url": "%s"}' % url_download
        myjson = json.dumps(json.loads(data))
        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
        try:
            r = requests.post(url, data=myjson, headers=headers)
            if r.status_code == HTTPStatus.OK:
                return json.loads(r.text)['hash']
            return "-1"
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            self._logger.warning("No se ha podido obtener el hash para %s", url_download)  # fixme traducir
            return None

    @staticmethod
    def get_dangerous_json(data: Dict, status_code: int):
        try:
            if 'error' in data.keys():
                return None
            # print(len(data))
            # print('error' in data.keys())
            # print('')
            # print(data)
            # si es correcto pero no tiene result es porque es un json con permalink
            if status_code == HTTPStatus.OK and data['results']['response_code'] == 1 and \
                    'positives' in data['results']:
                return data['results']['positives']
            elif status_code == HTTPStatus.OK and data['results']['response_code'] == 0:
                return -1  # ese hash es desconocido para vt
            return None
        except KeyError:
            print(data)
            return None


def create_arg() -> argparse:
    """
    Metodo para establecer los argumentos que necesita la clase

    :return:
    """
    config = configparser.ConfigParser()
    config.sections()
    config.read('../settings.conf')

    example = 'python3 %(prog)s -f ../output/cowrie.completed.json -ip "127.0.0.1:9200" -i cowrie-s2 ' \
              '-m mapping.json -v'
    my_parser = argparse.ArgumentParser(description='%(prog)s is a script to enter data in the elasticsearch database.',
                                        usage='{}'.format(example))

    my_parser.add_argument('-f', '--file', help='File to upload.')
    my_parser.add_argument('-m', '--mapping', help='Path of the file where the mapping of the attributes is defined.')
    my_parser.add_argument('-ip', '--ip', help='IP address of the server where ElasticSearch is located.')
    my_parser.add_argument('-i', '--index', help='Name of the index.')
    my_parser.add_argument('-b', '--bulk', action='store_true', help='bulk mode (boolean).', default=True)
    my_parser.add_argument('-u', '--update', action='store_true', help='update dangerous files (boolean).',
                           default=False)
    my_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose flag (boolean).', default=False)

    # tambien lo puedo poner en la misma linea
    my_parser.set_defaults(ip=config['DEFAULTS']['ELASTIC_IP'])
    my_parser.set_defaults(index=config['DEFAULTS']['ELASTIC_INDEX'])
    # myParser.print_help()
    return my_parser.parse_args()


if __name__ == '__main__':
    startTotal = timer()

    arg = create_arg()
    logger = functions.get_logger(arg.verbose, 'elk')

    e = Elastic(arg.ip, logger)

    if arg.mapping is not None:
        e.create_mapping(arg.index, arg.mapping)

    if arg.update:
        # Paso 1 crear json descargas y obtener el hash de cada uno
        e.create_json_downloads_pending(just_download=True)  # creo json de wget y curl que no existan
        e.create_json_downloads_pending(just_download=False)  # creo json de wget y curl que no existan

        # Paso 2 obtener la peligrodisdad de cada hash
        e.update_dangerous_files()

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
