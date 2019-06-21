#!/bin/env python3
# -*- coding: utf-8 -*-

from .table import Table


class TableDownloads(Table):
    """
    Clase que contiene los campos de la tabla downloads
    """

    def __init__(self, timestamp, url, outfile, shasum):
        """
        Constructor de clase

        :param timestamp:
        :param url:
        :param outfile:
        :param shasum:
        :return:
        """
        super().__init__()
        self._timestamp = timestamp
        self._url = url
        self._outfile = outfile
        self._shasum = shasum
        self._dangerous = 0

    def __getstate__(self):
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'timestamp': self._timestamp, 'url': self._url, 'outfile': self._outfile,
                'shasum': self._shasum, 'dangerous': self._dangerous}

    def isValid(self):
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._timestamp) > 0 and len(self._url) > 0 and len(self._outfile) > 0 and \
                len(self._shasum) > 0:
            return True
        return False
