#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import json
from timeit import default_timer as timer

from newConnection import NewConnection
from functions import checkDir


class CompleteSession(object):
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

        self._fileSession = '{}/{}'.format(output, config[myConfig]['FILE_LOG_SESSION'])
        self._fileNoSession = '{}/{}'.format(output, config[myConfig]['FILE_LOG_NOSESSION'])
        self._fileSessionOutput = '{}/{}'.format(output, config[myConfig]['FILE_LOG_COMPLETED'])
        self._fileNoSessionOutput = '{}/{}.2.json'.format(output, config[myConfig]['FILE_LOG_NOSESSION'])
        self._outputJson = str()
        self._jsonNonTrated = list()

        with open(self._fileNoSession, 'r') as f:
            self._linesNoSession = f.readlines()

    def search(self, lineSessionJson):
        """
        Metodo para comprobar si hay alguna linea de sesion no iniciada que coincide con una sesion iniciada dada

        :param lineSessionJson:
        :return:
        """
        # print(json.loads(lineSession))
        for lineNoSession in self._linesNoSession:
            lineNoSessionJson = json.loads(lineNoSession)
            if len(lineNoSession) > 2 and lineSessionJson['idip'] == lineNoSessionJson['idip']:
                a = NewConnection.fromJson(lineSessionJson, lineNoSessionJson)
                # print(a.getJSON())
                self._outputJson += a.getJSON()
                self._linesNoSession.remove(lineNoSession)  # Elimino la linea usada mejorado la eficiencia
                # print(len(self._linesNoSession))
                return True
        return False

    def writeLogSession(self):
        """
        Metodo que añade al fichero principal las sesiones que han sido recuperadas

        :return:
        """
        with open(self._fileSessionOutput, 'a') as f:
            f.write(self._outputJson)

    def writeLogNoSession(self):
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

        with open(self._fileNoSessionOutput, 'w') as f:
            f.write(log)

    def run(self):
        """
        Metodo para analizar todas las lineas del fichero de sesiones iniciadas pero no cerradas y guardar los
        resultados

        :return:
        """
        startTotal = timer()

        with open(self._fileSession, 'r') as f:
            totalLines = f.readlines()
            for num, lineSession in enumerate(totalLines):
                if self._verbose:
                    print('{}/{}'.format(num, len(totalLines)))
                if len(lineSession) > 2:  # Evitamos lineas en blanco (\n)
                    lineSessionJson = json.loads(lineSession)
                    utilizado = self.search(lineSessionJson)
                    if not utilizado:
                        self._jsonNonTrated.append(lineSessionJson)
                        # print('non update: {}'.format(lineSession.replace('\n', '')))

        self.writeLogSession()
        self.writeLogNoSession()

        endTotal = timer()
        print('Tiempo total: {} seg'.format(endTotal - startTotal))  # Time in seconds, e.g. 5.38091952400282
