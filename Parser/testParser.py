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

    def test_parserCompleted(self) -> NoReturn:
        """
        Comprueba que se crea bien el fichero con todas las conexiones completas

        :return:
        """
        myFileCorrect = '{}/unittest.completed.json'.format(self._config['UNITTEST']['OUTPUT'])
        fileInsert = '{}/{}'.format(self._config['UNITTEST']['OUTPUT'],
                                    self._config['UNITTEST']['FILE_LOG_COMPLETED'])

        parser = Parser(False, self._config['UNITTEST']['OUTPUT'], self._config['UNITTEST']['OUTPUT'], 'UNITTEST')
        parser.parse(self._config['UNITTEST']['BD_GEOIP2'])

        self.assertTrue(cmp(myFileCorrect, fileInsert))

    def test_parserSession(self) -> NoReturn:
        """
        Comprueba que se crea bien el fichero que tiene sesiones pero no ha finalizado la conexion

        :return:
        """
        myFileCorrect = '{}/unittest.session.json'.format(self._config['UNITTEST']['OUTPUT'])
        fileInsert = '{}/{}'.format(self._config['UNITTEST']['OUTPUT'],
                                    self._config['UNITTEST']['FILE_LOG_SESSION'])

        self.assertTrue(cmp(myFileCorrect, fileInsert))

    def test_parserNoSession(self) -> NoReturn:
        """
        Comprueba que se crea bien el fichero con lsa conexiones sin sesion
        
        :return:
        """
        myFileCorrect = '{}/unittest.nosession.json'.format(self._config['UNITTEST']['OUTPUT'])
        fileInsert = '{}/{}'.format(self._config['UNITTEST']['OUTPUT'],
                                    self._config['UNITTEST']['FILE_LOG_NOSESSION'])

        self.assertTrue(cmp(myFileCorrect, fileInsert))

    def test_CompleteSession(self) -> NoReturn:
        myFileCorrect = '{}/unittest.completed2.json'.format(self._config['UNITTEST']['OUTPUT'])
        fileInsert = '{}/{}'.format(self._config['UNITTEST']['OUTPUT'],
                                    self._config['UNITTEST']['FILE_LOG_COMPLETED'])
        print(myFileCorrect)
        print(fileInsert)
        c = CompleteSession(False, self._config['UNITTEST']['OUTPUT'], 'UNITTEST')
        c.run()
        self.assertTrue(cmp(myFileCorrect, fileInsert))

    def test_CompleteNoSession(self) -> NoReturn:
        myFileCorrect = '{}/unittest.nosession.json.2.json'.format(self._config['UNITTEST']['OUTPUT'])
        fileInsert = '{}/{}.2.json'.format(self._config['UNITTEST']['OUTPUT'],
                                           self._config['UNITTEST']['FILE_LOG_NOSESSION'])

        self.assertTrue(cmp(myFileCorrect, fileInsert))


if __name__ == "__main__":
    unittest.main()
