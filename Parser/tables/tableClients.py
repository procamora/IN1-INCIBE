#!/bin/env python3
# -*- coding: utf-8 -*-

from .table import Table


class TableClients(Table):
    """
    Clase que contiene los campos de la tabla clients
    """

    def __init__(self):
        """
        Constructor de clase
        """
        super().__init__()
        self._version = self._DEFAULT_VALUE
        self._shortName = self._DEFAULT_VALUE
        self._kexAlg = self._DEFAULT_VALUE
        self._keyAlg = self._DEFAULT_VALUE
        self._encryption = self._DEFAULT_VALUE
        self._authentication = self._DEFAULT_VALUE

    def load(self, version, shortName):
        """
        Metedo que carga los principales valores de la tabla

        :param version:
        :param shortName:
        :return:
        """
        if len(version) > 0 and version != self._DEFAULT_VALUE:
            self._version = version
        if len(shortName) > 0 and shortName != self._DEFAULT_VALUE:
            self._shortName = shortName

    def setKexAlg(self, kexAlg):
        if len(kexAlg) > 0 and kexAlg != self._DEFAULT_VALUE:
            self._kexAlg = kexAlg

    def setKeyAlg(self, keyAlg):
        if len(keyAlg) > 0 and keyAlg != self._DEFAULT_VALUE:
            self._keyAlg = keyAlg

    def setEncryption(self, encryption):
        if len(encryption) > 0 and encryption != self._DEFAULT_VALUE:
            self._encryption = encryption

    def setAuthentication(self, authentication):
        if len(authentication) > 0:
            self._authentication = authentication

    def __getstate__(self):
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'version': self._version, 'shortName': self._shortName, 'kexAlg': self._kexAlg, 'keyAlg': self._keyAlg,
                'encryption': self._encryption, 'authentication': self._authentication,
                'eventid': 'cowrie.client.version'}

    def isValid(self):
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._version) > 0:
            return True
        return False
