#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import json
import logging
from timeit import default_timer as timer

from functions import checkDir, writeFile
from newConnection import NewConnection


class Compatible(object):
    def __init__(self, logger, directory, myConfig):
        """
        Constructor de clase

        :param logger:
        :param directory: Directorio donde se guardan los ficheros de salida
        """
        config = configparser.ConfigParser()
        config.sections()
        config.read('settings.conf')

        checkDir(directory)

        self._logger = logger

        self._fileCompleted = '{}/{}'.format(directory, config[myConfig]['FILE_LOG_COMPLETED'])
        self._outputJson = '{}/{}'.format(directory, config[myConfig]['FILE_LOG_COWRIE'])

    def run(self):
        """
        Metodo para analizar todas las lineas del fichero de sesiones iniciadas pero no cerradas y guardar los
        resultados

        :return:
        """
        output = str()
        start = timer()
        with open(self._fileCompleted, 'r') as f:
            totalLines = f.readlines()
            for num, lineSession in enumerate(totalLines):
                logging.debug('{}/{}'.format(num + 1, len(totalLines)))
                if len(lineSession) > 2:  # Evitamos lineas en blanco (\n)
                    n = NewConnection.fromJson(json.loads(lineSession), json.loads('{}'), False)
                    output = '{}{}'.format(output, n.getJSONCowrie())
        end = timer()
        logging.debug('Time total: {}'.format(end - start))  # Time in seconds

        writeFile(output, self._outputJson, 'w')
