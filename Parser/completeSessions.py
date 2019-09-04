#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import json
import logging
from timeit import default_timer as timer
from typing import NoReturn

from newConnection import NewConnection
from utils.functions import check_dir, write_file


class CompleteSession(object):
    def __init__(self, logger: logging, output: str, my_config: str) -> NoReturn:
        """
        Constructor de clase

        :param logger:
        :param output: Directorio donde se guardan los ficheros de salida
        """
        config = configparser.ConfigParser()
        config.sections()
        config.read('settings.conf')

        check_dir(output)

        self._logger = logger

        self._file_session = '{}/{}'.format(output, config[my_config]['FILE_LOG_SESSION'])
        self._file_no_session = '{}/{}'.format(output, config[my_config]['FILE_LOG_NOSESSION'])
        self._file_session_output = '{}/{}'.format(output, config[my_config]['FILE_LOG_COMPLETED'])
        self._file_no_session_output = '{}/{}.2.json'.format(output, config[my_config]['FILE_LOG_NOSESSION'])
        self._output_json = str()
        self._json_non_trated = list()

        with open(self._file_no_session, 'r') as f:
            self._lines_no_session = f.readlines()

    def search(self, line_session_json: dict) -> bool:
        """
        Metodo para comprobar si hay alguna linea de sesion no iniciada que coincide con una sesion iniciada dada

        :param line_session_json:
        :return:
        """
        for line_no_session in self._lines_no_session:
            line_no_session_json = json.loads(line_no_session)
            if len(line_no_session) > 2 and line_session_json['idip'] == line_no_session_json['idip']:
                a = NewConnection.from_json(line_session_json, line_no_session_json)
                self._output_json += a.get_json()
                self._lines_no_session.remove(line_no_session)  # Elimino la linea usada mejorado la eficiencia
                return True
        return False

    def write_log_session(self) -> NoReturn:
        """
        Metodo que añade al fichero principal las sesiones que han sido recuperadas

        :return:
        """
        write_file(self._output_json, self._file_session_output, 'a')

    def write_log_no_session(self) -> NoReturn:
        """
        Metodo que crea un fichero auxiliar con la informacion geografica de las ip's de las sesiones que no han
        sido capaz de recuperarse

        :return:
        """
        log = str()

        for i in self._json_non_trated:
            log += '{}\n'.format(json.dumps(i['geoip']))

        for i in self._lines_no_session:
            j = json.loads(i)['geoip']
            log += '{}\n'.format(json.dumps(j))

        write_file(log, self._file_no_session_output, 'w')

    def run(self) -> NoReturn:
        """
        Metodo para analizar todas las lineas del fichero de sesiones iniciadas pero no cerradas y guardar los
        resultados

        :return:
        """
        start_total = timer()

        with open(self._file_session, 'r') as f:
            total_lines = f.readlines()
            count_lines = len(total_lines)
            for num, lineSession in enumerate(total_lines):
                if num % 500 == 0:  # imprimimos cada 500 lineas
                    self._logger.debug('{}/{}'.format(num, count_lines))
                if len(lineSession) > 2:  # Evitamos lineas en blanco (\n)
                    line_session_json = json.loads(lineSession)
                    utilizado = self.search(line_session_json)
                    if not utilizado:
                        self._json_non_trated.append(line_session_json)
            self._logger.debug('{}/{}'.format(count_lines, count_lines))

        self.write_log_session()
        self.write_log_no_session()

        end_total = timer()
        self._logger.info('Time total: {} seg'.format(end_total - start_total))  # Time in seconds, e.g. 5.3802
