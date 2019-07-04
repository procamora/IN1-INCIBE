#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import json
from timeit import default_timer as timer
from typing import NoReturn

from newConnection import NewConnection
from utils.functions import checkDir, writeFile


class Compatible(object):
    def __init__(self, logger, directory, myConfig) -> NoReturn:
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

    def run(self) -> NoReturn:
        """
        Metodo para analizar todas las lineas del fichero de sesiones iniciadas pero no cerradas y guardar los
        resultados

        :return:
        """
        output = str()
        start = timer()
        writeFile(output, self._outputJson, 'w')

        with open(self._fileCompleted, 'r') as f:
            totalLines = f.readlines()
            for num, lineSession in enumerate(totalLines):
                if num % 2000 == 0:  # imprimimos cada 500 lineas
                    self._logger.debug('{}/{}'.format(num, len(totalLines)))
                    # Guaredo n conexiones y reinicio el string
                    writeFile(output, self._outputJson, 'a')
                    output = str()
                if len(lineSession) > 2:  # Evitamos lineas en blanco (\n)
                    n = NewConnection.fromJson(json.loads(lineSession), json.loads('{}'), False)
                    output = '{}{}'.format(output, n.getJSONCowrie())
            self._logger.debug('{}/{}'.format(len(totalLines), len(totalLines)))
        # imprimo las ultimas lineas
        writeFile(output, self._outputJson, 'a')

        end = timer()
        self._logger.info('Time total: {}'.format(end - start))  # Time in seconds
