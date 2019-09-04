#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import json
import logging
from timeit import default_timer as timer
from typing import NoReturn

from newConnection import NewConnection
from utils.functions import check_dir, write_file, get_number_lines_file


class Compatible(object):
    def __init__(self, logger: logging, directory: str, my_config: str) -> NoReturn:
        """
        Constructor de clase

        :param logger:
        :param directory: Directorio donde se guardan los ficheros de salida
        """
        config = configparser.ConfigParser()
        config.sections()
        config.read('settings.conf')

        check_dir(directory)

        self._logger = logger

        self._fileCompleted = '{}/{}'.format(directory, config[my_config]['FILE_LOG_COMPLETED'])
        self._outputJson = '{}/{}'.format(directory, config[my_config]['FILE_LOG_COWRIE'])
        self._dict_reputation_ip = dict()

    def run(self) -> NoReturn:
        """
        Metodo para analizar todas las lineas del fichero de sesiones iniciadas pero no cerradas y guardar los
        resultados

        :return:
        """
        output = str()
        start = timer()
        write_file(output, self._outputJson, 'w')

        with open(self._fileCompleted, 'r') as f:
            cont_progress = 0
            count_lines = get_number_lines_file(self._fileCompleted, self._logger)
            for lineSession in f:
                cont_progress += 1
                if cont_progress % 2000 == 0:  # imprimimos cada 500 lineas
                    self._logger.debug('{}/{}'.format(cont_progress, count_lines))
                    # Guaredo n conexiones y reinicio el string
                    write_file(output, self._outputJson, 'a')
                    output = str()
                if len(lineSession) > 2:  # Evitamos lineas en blanco (\n)
                    n = NewConnection.from_json(json.loads(lineSession), json.loads('{}'), False)
                    output = '{}{}'.format(output, n.get_json_cowrie(self._logger, self._dict_reputation_ip))
            self._logger.debug('{}/{}'.format(count_lines, count_lines))
        # imprimo las ultimas lineas
        write_file(output, self._outputJson, 'a')

        self._logger.debug(f'Size dictionary reputation ip: {len(self._dict_reputation_ip)}')
        end = timer()
        self._logger.info('Time total: {}'.format(end - start))  # Time in seconds
