#!/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import json
import sys
from timeit import default_timer as timer

import requests
from elasticsearch import Elasticsearch

from functions import getLogger


class Elastic(object):
    def __init__(self, ip, logger):
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

    def addMapping(self, myIndex, fileMapping):
        with open(fileMapping, 'r') as fp:
            mapping = fp.read()

        # create an index in elasticsearch, ignore status code 400 (index already exists)
        try:
            self._es.indices.create(index=myIndex, body=mapping)  # , ignore=400)
        except:
            self._logger.error("Index: {} already exists".format(myIndex))
        self._logger.info('Create index')

    def insert(self, myIndex, file):
        with open(file, 'r') as open_file:
            for entry in open_file:
                if len(entry) > 2:  # evitar lineas en blanco "\n"
                    self._es.index(index=myIndex, doc_type=self._doc_type, body=entry)
        # print('index: ' + res['result'])
        # but not deserialized
        # res = self._es.get(index=myIndex, doc_type=self._doc_type)
        # print('get: ' + str(res['_source']))
        # self._es.indices.refresh(index=myIndex)

    def bulk(self, myIndex, file):
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
                    entry = self.updateDownload(entry)
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

    def isError(self, response):
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

    def updateDangerousFiles(self):
        self._logger.info('Update downloaded files')
        jsonSearch = \
            {
                "query": {
                    "term": {"dangerous": -1}
                }
            }
        res = self._es.search(body=jsonSearch)
        self._logger.info("Got {} pending files".format(res['hits']['total']))

        for hit in res['hits']['hits']:
            self._logger.debug(hit['_source'])
            positives = self.urlAnalize(hit['_source']['url'])
            if positives is not None:
                jsonUpdate = \
                    {
                        "doc": {
                            "dangerous": positives
                        }
                    }
                self._es.update(index=hit['_index'], doc_type=hit['_type'], id=hit['_id'], body=jsonUpdate)
            #

    def updateDownload(self, entry):
        t = json.loads(entry)
        if 'dangerous' in t:
            self._logger.info(t)
            positives = self.md5(t['shasum'])
            if positives is not None:
                self._logger.info('ACTUALIZAMOS CON {}'.format(positives))
                t['dangerous'] = positives
                self._logger.debug(entry)
        return json.dumps(t)

    def md5(self, md5hex):
        url = '{}/analize?md5={}'.format(self._URL, md5hex)
        headers = {'Accept': 'application/json'}
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                return json.loads(r.text)['results']['positives']
            return None
        except requests.exceptions.ConnectionError:
            self._logger.warning("No se ha podido comprobar el hash")  # fixme traducir
            return None

    def urlAnalize(self, url_analize):
        data = '''{"url": "%s"}''' % url_analize
        myjson = json.dumps(json.loads(data))
        url = '{}/analize'.format(self._URL)
        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

        try:
            r = requests.post(url, data=myjson, headers=headers)
            if r.status_code == 200:
                return json.loads(r.text)['results']['positives']
            return None
        except requests.exceptions.ConnectionError:
            self._logger.warning("No se ha podido comprobar la url")  # fixme traducir
            return 23


def CreateArgParser():
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
        e.updateDangerousFiles()
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
