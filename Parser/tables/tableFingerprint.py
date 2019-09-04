#!/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from typing import NoReturn, Dict, Any

from .table import Table


@dataclass(order=True)
class TableFingerprint(Table):
    """
    Clase que contiene los campos de la tabla fingerprint
    """

    def __init__(self) -> NoReturn:
        """
        Constructor de clase
        """
        super().__init__()
        self._fingerprint: str = str()

    def set_fingerprint(self, fingerprint) -> NoReturn:
        """
        Metedo que carga los principales valores de la tabla

        :param fingerprint:
        :return:
        """
        if len(fingerprint) > 0:
            self._fingerprint = fingerprint

    def __getstate__(self) -> Dict[str, Any]:
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'fingerprint': self._fingerprint, 'eventid': 'cowrie.client.fingerprint'}

    def is_valid(self) -> bool:
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._fingerprint) > 0:
            return True
        return False
