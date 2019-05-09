#!/bin/env python3
# -*- coding: utf-8 -*-

from .table import Table


class TableAuth(Table):
    """
    Clase que contiene los campos de la tabla auth
    """

    def __init__(self):
        """
        Constructor de clase
        """
        super().__init__()
        self._success = -1
        self._username = str()
        self._password = str()
        self._timestamp = str()

    def load(self, success, username, password, timestamp):
        """
        Metedo que carga los principales valores de la tabla

        :param success:
        :param username:
        :param password:
        :param timestamp:
        :return:
        """
        self._success = int(success)
        self._username = username
        self._password = password
        self._timestamp = timestamp

    def __getstate__(self):
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'success': self._success, 'username': self._username, 'password': self._password,
                'timestamp': self._timestamp, 'credentials': '{}/{}'.format(self._username, self._password)}

    def isValid(self):
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios
        :return: bool
        """
        if len(self._username) > 0 and len(self._password) > 0 and len(
                self._timestamp) > 0:
            return True
        return False
