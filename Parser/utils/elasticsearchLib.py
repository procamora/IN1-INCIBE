#!/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import json
from timeit import default_timer as timer

from elasticsearch import Elasticsearch


class Elastic(object):
    def __init__(self, ip, verbose):
        self._es = Elasticsearch(
            [ip],
            # http_auth=('user', 'secret'),
            # scheme="http",
            verify_certs = True
        )

        if not self._es.ping():
            raise ValueError("Connection failed, Exiting!!")

        self._verbose = verbose
        self._doc_type = 'nested'

    def addMapping(self, myIndex, fileMapping):
        with open(fileMapping, 'r') as fp:
            mapping = fp.read()

        # create an index in elasticsearch, ignore status code 400 (index already exists)
        self._es.indices.create(index=myIndex, body=mapping)  # , ignore=400)
        print('Create index')

    def insert(self, myIndex, file):
        with open(file, 'r') as open_file:
            for entry in open_file:
                if len(entry) > 2: # evitar lineas en blanco "\n"
                    res = self._es.index(index=myIndex, doc_type='object', body=entry)
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
            body = []
            for entry in open_file:
                body.append({'index': {'_id': idElk}})
                body.append(entry)
                if len(body) > incremet:
                    contProgress += (incremet // 2)
                    if self._verbose:
                        print('{}/{}'.format(contProgress, count_lines))
                    self._es.bulk(body, index=myIndex, doc_type=self._doc_type)
                    body.clear()
                idElk += 1

            if len(body) != 0:
                if self._verbose:
                    print('body != 0')
                self._es.bulk(body, index=myIndex, doc_type=self._doc_type)

    def search(self, myIndex):
        res = self._es.search(index=myIndex, body={"query": {"match_all": {}}})
        print(res)
        print("Got %d Hits:" % res['hits']['total'])
        # for hit in res['hits']['hits']:
        #    print("%(timestamp)s %(author)s: %(text)s num: %(num)i" % hit["_source"])


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

    requiredNamed = myParser.add_argument_group('required named arguments')
    requiredNamed.add_argument('-f', '--file', required=True, help='File to upload.')

    myParser.add_argument('-m', '--mapping', help='Path of the file where the mapping of the attributes is defined.')
    myParser.add_argument('-ip', '--ip', help='IP address of the server where ElasticSearch is located.')
    myParser.add_argument('-i', '--index', help='Name of the index.')
    myParser.add_argument('-b', '--bulk', action='store_true', help='bulk mode (boolean).', default=True)
    myParser.add_argument('-v', '--verbose', action='store_true', help='Verbose flag (boolean).', default=False)

    # tambien lo puedo poner en la misma linea
    myParser.set_defaults(ip=config['DEFAULTS']['ELASTIC_IP'])
    myParser.set_defaults(index=config['DEFAULTS']['ELASTIC_INDEX'])
    # myParser.print_help()
    return myParser.parse_args()


if __name__ == '__main__':
    startTotal = timer()

    arg = CreateArgParser()

    e = Elastic(arg.ip, arg.verbose)

    if arg.mapping is not None:
        e.addMapping(arg.index, arg.mapping)

    if arg.bulk:
        e.bulk(arg.index, arg.file)
    else:
        e.insert(arg.index, arg.file)

    endTotal = timer()
    if arg.verbose:
        print('Tiempo total: {} seg'.format(endTotal - startTotal))  # Time in seconds, e.g. 5.38091952400282

