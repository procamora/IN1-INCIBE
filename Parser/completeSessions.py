#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import json
from timeit import default_timer as timer
from typing import NoReturn

from newConnection import NewConnection
from utils.functions import checkDir, writeFile


class CompleteSession(object):
    def __init__(self, logger, output, myConfig) -> NoReturn:
        """
        Constructor de clase

        :param logger:
        :param output: Directorio donde se guardan los ficheros de salida
        """
        config = configparser.ConfigParser()
        config.sections()
        config.read('settings.conf')

        checkDir(output)

        self._logger = logger

        self._fileSession = '{}/{}'.format(output, config[myConfig]['FILE_LOG_SESSION'])
        self._fileNoSession = '{}/{}'.format(output, config[myConfig]['FILE_LOG_NOSESSION'])
        self._fileSessionOutput = '{}/{}'.format(output, config[myConfig]['FILE_LOG_COMPLETED'])
        self._fileNoSessionOutput = '{}/{}.2.json'.format(output, config[myConfig]['FILE_LOG_NOSESSION'])
        self._outputJson = str()
        self._jsonNonTrated = list()

        with open(self._fileNoSession, 'r') as f:
            self._linesNoSession = f.readlines()

    def search(self, lineSessionJson) -> bool:
        """
        Metodo para comprobar si hay alguna linea de sesion no iniciada que coincide con una sesion iniciada dada

        :param lineSessionJson:
        :return:
        """
        for lineNoSession in self._linesNoSession:
            lineNoSessionJson = json.loads(lineNoSession)
            if len(lineNoSession) > 2 and lineSessionJson['idip'] == lineNoSessionJson['idip']:
                a = NewConnection.fromJson(lineSessionJson, lineNoSessionJson)
                self._outputJson += a.getJSON()
                self._linesNoSession.remove(lineNoSession)  # Elimino la linea usada mejorado la eficiencia
                return True
        return False

    def writeLogSession(self) -> NoReturn:
        """
        Metodo que añade al fichero principal las sesiones que han sido recuperadas

        :return:
        """
        writeFile(self._outputJson, self._fileSessionOutput, 'a')

    def writeLogNoSession(self) -> NoReturn:
        """
        Metodo que crea un fichero auxiliar con la informacion geografica de las ip's de las sesiones que no han
        sido capaz de recuperarse

        :return:
        """
        log = str()

        for i in self._jsonNonTrated:
            log += '{}\n'.format(json.dumps(i['geoip']))

        for i in self._linesNoSession:
            j = json.loads(i)['geoip']
            log += '{}\n'.format(json.dumps(j))

        writeFile(log, self._fileNoSessionOutput, 'w')

    def run(self) -> NoReturn:
        """
        Metodo para analizar todas las lineas del fichero de sesiones iniciadas pero no cerradas y guardar los
        resultados

        :return:
        """
        startTotal = timer()

        with open(self._fileSession, 'r') as f:
            totalLines = f.readlines()
            count_lines = len(totalLines)
            for num, lineSession in enumerate(totalLines):
                if num % 500 == 0:  # imprimimos cada 500 lineas
                    self._logger.debug('{}/{}'.format(num, count_lines))
                if len(lineSession) > 2:  # Evitamos lineas en blanco (\n)
                    lineSessionJson = json.loads(lineSession)
                    utilizado = self.search(lineSessionJson)
                    if not utilizado:
                        self._jsonNonTrated.append(lineSessionJson)
            self._logger.debug('{}/{}'.format(count_lines, count_lines))

        self.writeLogSession()
        self.writeLogNoSession()

        endTotal = timer()
        self._logger.info('Time total: {} seg'.format(endTotal - startTotal))  # Time in seconds, e.g. 5.3802
