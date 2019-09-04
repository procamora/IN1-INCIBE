#!/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from typing import NoReturn, Dict, Any

from .table import Table


@dataclass(order=True)
class TableDownloads(Table):
    """
    Clase que contiene los campos de la tabla downloads
    """

    def __init__(self, timestamp, url, outfile, shasum) -> NoReturn:
        """
        Constructor de clase

        :param timestamp:
        :param url:
        :param outfile:
        :param shasum:
        :return:
        """
        super().__init__()
        self._timestamp: str = timestamp
        self._url: str = url
        self._outfile: str = outfile
        self._shasum: str = shasum
        self._dangerous: int = -1  # no analizado

    def __getstate__(self) -> Dict[str, Any]:
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'timestamp': self._timestamp, 'url': self._url, 'outfile': self._outfile,
                'shasum': self._shasum, 'dangerous': self._dangerous, 'eventid': 'cowrie.session.file_download'}

    def is_valid(self) -> bool:
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._timestamp) > 0 and len(self._url) > 0 and len(self._outfile) > 0 and \
                len(self._shasum) > 0:
            return True
        return False
