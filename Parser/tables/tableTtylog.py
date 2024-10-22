#!/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from typing import NoReturn, Dict, Any

from .table import Table


@dataclass(order=True)
class TableTtylog(Table):
    """
    Clase que contiene los campos de la tabla ttylog
    """

    def __init__(self) -> NoReturn:
        """
        Constructor de clase
        """
        super().__init__()
        self._ttylog: str = self._DEFAULT_VALUE
        self._size: int = -1

    def set_size(self, size) -> NoReturn:
        """
        Metodo para establecer el tamaño de la ttylog

        :param size:
        :return:
        """
        if size != -1:
            self._size = int(size)

    def set_ttylog(self, ttylog) -> NoReturn:
        """
        Metedo que carga los principales valores de la tabla

        :param ttylog:
        :return:
        """
        if len(ttylog) > 0 and ttylog != self._DEFAULT_VALUE:
            self._ttylog = ttylog

    def __getstate__(self) -> Dict[str, Any]:
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'ttylog': self._ttylog, 'size': self._size, 'eventid': 'cowrie.log.closed'}

    def is_valid(self) -> bool:
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._ttylog) > 0:
            return True
        return False
