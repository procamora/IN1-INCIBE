 
#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import json
import re
import sys
from http import HTTPStatus  # https://docs.python.org/3/library/http.html
from timeit import default_timer as timer
from typing import NoReturn, Dict, Any, Union, List

import requests
from elasticsearch import Elasticsearch, exceptions
import functions
from datetime import datetime
import numpy
from scipy import stats


TIMEOUT = 600

def imprimir(texto, valor):
    print('{} {}\n'.format(texto, valor))

def promedio(datos):
    sumatoria = sum(datos)
    imprimir('La sumatoria es: ', sumatoria)

    longitud = float(len(datos))
    imprimir('La longitud es: ', longitud)

    resultado = sumatoria / longitud
    imprimir('El resultado es: ', resultado)

def moda(datos):
    repeticiones = 0

    for i in datos:
        n = datos.count(i)
        if n > repeticiones:
            repeticiones = n

    moda = [] #Arreglo donde se guardara el o los valores de mayor frecuencia 

    for i in datos:
        n = datos.count(i) # Devuelve el número de veces que x aparece enla lista.
        if n == repeticiones and i not in moda:
            moda.append(i)

    if len(moda) != len(datos):
        imprimir ('Moda: ', moda)
    else:
        print ('No hay moda')

def media(datos):
    datos.sort() #.sort Ordena los ítems dela lista

    if len(datos) % 2 == 0:
        n = len(datos)
        mediana = (datos[int(n / 2 - 1)] + datos[int(n / 2)]) / 2
    else:
        mediana = datos[int(len(datos) / 2)]

    imprimir ('Media: ', mediana)


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


    def process_hits_update_dangerous_files(self, hits: Dict, list_median: List) -> List:
        print(len(list_median))
        self._logger.info(f"Got {len(hits)} files")
        for hit in hits:
            da = datetime.strptime(hit['_source']['starttime'], '%Y-%m-%d %H:%M:%S')
            db = datetime.strptime(hit['_source']['endtime'], '%Y-%m-%d %H:%M:%S')
            result = int((db-da).total_seconds())
            if result > 0 and result <= 180:
                list_median.append(result)
            if result > 3000:
                self._logger.info(result)
                self._logger.info(hit['_source']['starttime'])
                self._logger.info(hit['_source']['endtime'])

        return list_median
            

    def update_dangerous_files(self) -> NoReturn:
        """
        Metodo que se ejecuta en el segundo paso, busca todos las descargas que tengan un -1 he intenta actualizar a su
        valor real
        :return:
        """
        self._logger.info('Step 2: Update downloaded files')

        json_search_dangerous_unused = \
            {
                "size": 5000,
                "query": {
                    "term": {"eventid": "cowrie.session"}
                }
            }

        response = self._es.search(body=json_search_dangerous_unused, scroll='2m')

        # fuente https://gist.github.com/hmldd/44d12d3a61a8d8077a3091c4ff7b9307
        # Get the scroll ID
        sid = response['_scroll_id']
        scroll_size = len(response['hits']['hits'])
        list_median = list()
        # Before scroll, process current batch of hits
        list_median = self.process_hits_update_dangerous_files(response['hits']['hits'], list_median)

        while scroll_size > 0:
            "Scrolling..."
            response = self._es.scroll(scroll_id=sid, scroll='2m')
            # Process current batch of hits
            list_median = self.process_hits_update_dangerous_files(response['hits']['hits'], list_median)
            # Update the scroll ID
            sid = response['_scroll_id']
            # Get the number of results that returned in the last scroll
            scroll_size = len(response['hits']['hits'])

        #promedio(list_median)
        #moda(list_median)
        #media(list_median)
        self._logger.info(f"Moda: {stats.mode(list_median)}")
        self._logger.info(f"Media: {numpy.mean(list_median)}")
        self._logger.info(f"Mediana: {numpy.median(list_median)}")


if __name__ == '__main__':
    startTotal = timer()

    logger = functions.get_logger(True, 'elk')
    e = Elastic("127.0.0.1", logger)
    e.update_dangerous_files() 


    endTotal = timer()
    logger.debug('Tiempo total: {} seg'.format(endTotal - startTotal))  # Time in seconds, e.g. 5.38
