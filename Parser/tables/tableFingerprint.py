#!/bin/env python3
# -*- coding: utf-8 -*-

from .table import Table


class TableFingerprint(Table):
    """
    Clase que contiene los campos de la tabla fingerprint
    """

    def __init__(self):
        """
        Constructor de clase
        """
        super().__init__()
        self._fingerprint = str()

    def setFingerprint(self, fingerprint):
        """
        Metedo que carga los principales valores de la tabla

        :param fingerprint:
        :return:
        """
        if len(fingerprint) > 0:
            self._fingerprint = fingerprint

    def __getstate__(self):
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'fingerprint': self._fingerprint}

    def isValid(self):
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._fingerprint) > 0:
            return True
        return False
