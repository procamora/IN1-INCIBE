#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import json
from timeit import default_timer as timer

from newConnection import NewConnection
from functions import checkDir


class Compatible(object):
    def __init__(self, verbose, output, myConfig):
        """
        Constructor de clase

        :param verbose:
        :param output: Directorio donde se guardan los ficheros de salida
        """
        config = configparser.ConfigParser()
        config.sections()
        config.read('settings.conf')

        checkDir(output)

        self._verbose = verbose

        self._fileCompleted = '{}/{}'.format(output, config[myConfig]['FILE_LOG_COMPLETED'])
        self._outputJson = str()
        self._jsonNonTrated = list()


    def run(self):
        """
        Metodo para analizar todas las lineas del fichero de sesiones iniciadas pero no cerradas y guardar los
        resultados

        :return:
        """
        startTotal = timer()

        with open(self._fileCompleted, 'r') as f:
            totalLines = f.readlines()
            for num, lineSession in enumerate(totalLines):
                if self._verbose:
                    print('{}/{}'.format(num, len(totalLines)))
                if len(lineSession) > 2:  # Evitamos lineas en blanco (\n)
                    n = NewConnection.fromJson(json.loads(lineSession), json.loads('{}'), False)
                    print(n.getJSONCowrie())


        endTotal = timer()
        print('Tiempo total: {} seg'.format(endTotal - startTotal))  # Time in seconds, e.g. 5.38091952400282



c = Compatible(False, 'testing123', 'DEFAULTS')
c.run()