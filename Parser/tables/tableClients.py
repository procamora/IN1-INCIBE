#!/bin/env python3
# -*- coding: utf-8 -*-
from dataclasses import dataclass
from typing import NoReturn, Dict, Any

from .table import Table


@dataclass(order=True)
class TableClients(Table):
    """
    Clase que contiene los campos de la tabla clients
    """

    def __init__(self) -> NoReturn:
        """
        Constructor de clase
        """
        super().__init__()
        self._version: str = self._DEFAULT_VALUE
        self._shortName: str = self._DEFAULT_VALUE
        self._kexAlg: str = self._DEFAULT_VALUE
        self._keyAlg: str = self._DEFAULT_VALUE
        self._encryption: str = self._DEFAULT_VALUE
        self._authentication: str = self._DEFAULT_VALUE

    def load(self, version, shortName) -> NoReturn:
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

    def setKexAlg(self, kexAlg) -> NoReturn:
        if len(kexAlg) > 0 and kexAlg != self._DEFAULT_VALUE:
            self._kexAlg = kexAlg

    def setKeyAlg(self, keyAlg) -> NoReturn:
        if len(keyAlg) > 0 and keyAlg != self._DEFAULT_VALUE:
            self._keyAlg = keyAlg

    def setEncryption(self, encryption) -> NoReturn:
        if len(encryption) > 0 and encryption != self._DEFAULT_VALUE:
            self._encryption = encryption

    def setAuthentication(self, authentication) -> NoReturn:
        if len(authentication) > 0:
            self._authentication = authentication

    def __getstate__(self) -> Dict[str, Any]:
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'version': self._version, 'shortName': self._shortName, 'kexAlg': self._kexAlg, 'keyAlg': self._keyAlg,
                'encryption': self._encryption, 'authentication': self._authentication,
                'eventid': 'cowrie.client.version'}

    def isValid(self) -> bool:
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._version) > 0:
            return True
        return False
