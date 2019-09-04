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
        self._short_name: str = self._DEFAULT_VALUE
        self._kex_alg: str = self._DEFAULT_VALUE
        self._key_alg: str = self._DEFAULT_VALUE
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
            self._short_name = shortName

    def set_kex_alg(self, kexAlg) -> NoReturn:
        if len(kexAlg) > 0 and kexAlg != self._DEFAULT_VALUE:
            self._kex_alg = kexAlg

    def set_key_alg(self, keyAlg) -> NoReturn:
        if len(keyAlg) > 0 and keyAlg != self._DEFAULT_VALUE:
            self._key_alg = keyAlg

    def set_encryption(self, encryption) -> NoReturn:
        if len(encryption) > 0 and encryption != self._DEFAULT_VALUE:
            self._encryption = encryption

    def set_authentication(self, authentication) -> NoReturn:
        if len(authentication) > 0:
            self._authentication = authentication

    def __getstate__(self) -> Dict[str, Any]:
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'version': self._version, 'shortName': self._short_name, 'kexAlg': self._kex_alg, 'keyAlg': self._key_alg,
                'encryption': self._encryption, 'authentication': self._authentication,
                'eventid': 'cowrie.client.version'}

    def is_valid(self) -> bool:
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._version) > 0:
            return True
        return False
