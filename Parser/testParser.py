#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import unittest
from filecmp import cmp
from typing import NoReturn

from completeSessions import CompleteSession
from parser import Parser


class TestMyModule(unittest.TestCase):
    def setUp(self) -> NoReturn:
        self._config = configparser.ConfigParser()
        self._config.sections()
        self._config.read('settings.conf')

    def test_parser_completed(self) -> NoReturn:
        """
        Comprueba que se crea bien el fichero con todas las conexiones completas

        :return:
        """
        my_file_correct = '{}/unittest.completed.json'.format(self._config['UNITTEST']['OUTPUT'])
        file_insert = '{}/{}'.format(self._config['UNITTEST']['OUTPUT'],
                                     self._config['UNITTEST']['FILE_LOG_COMPLETED'])

        parser = Parser(False, self._config['UNITTEST']['OUTPUT'], self._config['UNITTEST']['OUTPUT'], 'UNITTEST')
        parser.parse(self._config['UNITTEST']['BD_GEOIP2'])

        self.assertTrue(cmp(my_file_correct, file_insert))

    def test_parser_session(self) -> NoReturn:
        """
        Comprueba que se crea bien el fichero que tiene sesiones pero no ha finalizado la conexion

        :return:
        """
        my_file_correct = '{}/unittest.session.json'.format(self._config['UNITTEST']['OUTPUT'])
        file_insert = '{}/{}'.format(self._config['UNITTEST']['OUTPUT'],
                                     self._config['UNITTEST']['FILE_LOG_SESSION'])

        self.assertTrue(cmp(my_file_correct, file_insert))

    def test_parser_no_session(self) -> NoReturn:
        """
        Comprueba que se crea bien el fichero con lsa conexiones sin sesion
        
        :return:
        """
        my_file_correct = '{}/unittest.nosession.json'.format(self._config['UNITTEST']['OUTPUT'])
        file_insert = '{}/{}'.format(self._config['UNITTEST']['OUTPUT'],
                                     self._config['UNITTEST']['FILE_LOG_NOSESSION'])

        self.assertTrue(cmp(my_file_correct, file_insert))

    def test_complete_session(self) -> NoReturn:
        my_file_correct = '{}/unittest.completed2.json'.format(self._config['UNITTEST']['OUTPUT'])
        file_insert = '{}/{}'.format(self._config['UNITTEST']['OUTPUT'],
                                     self._config['UNITTEST']['FILE_LOG_COMPLETED'])
        print(my_file_correct)
        print(file_insert)
        c = CompleteSession(False, self._config['UNITTEST']['OUTPUT'], 'UNITTEST')
        c.run()
        self.assertTrue(cmp(my_file_correct, file_insert))

    def test_CompleteNoSession(self) -> NoReturn:
        my_file_correct = '{}/unittest.nosession.json.2.json'.format(self._config['UNITTEST']['OUTPUT'])
        file_insert = '{}/{}.2.json'.format(self._config['UNITTEST']['OUTPUT'],
                                            self._config['UNITTEST']['FILE_LOG_NOSESSION'])

        self.assertTrue(cmp(my_file_correct, file_insert))


if __name__ == "__main__":
    unittest.main()
