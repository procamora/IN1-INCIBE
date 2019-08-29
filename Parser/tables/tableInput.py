#!/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from typing import NoReturn, Dict, Any

from .table import Table


@dataclass(order=True)
class TableInput(Table):
    """
    Clase que contiene los campos de la tabla input
    """

    def __init__(self) -> NoReturn:
        """
        Constructor de clase
        """
        super().__init__()
        self._timestamp: str = str()
        self._success: int = -1
        self._input: str = str()

    def set_success(self, success) -> NoReturn:
        """
        Metodo para establecer el valor de la ejecucion de un comando (valido/invalido)

        :param success:
        :return:
        """
        self._success = int(success)

    def get_input(self) -> NoReturn:
        """
        Metodo para obtener el valor de _input, corresponde con el comando ejecutado

        :return:
        """
        return self._input

    def load(self, timestamp, myInput) -> NoReturn:
        """
        Metedo que carga los principales valores de la tabla

        :param timestamp:
        :param myInput:
        :return:
        """
        self._timestamp = timestamp
        self._input = myInput

    def __getstate__(self) -> Dict[str, Any]:
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'timestamp': self._timestamp, 'success': self._success, 'input': self._input,
                'eventid': 'cowrie.command.input'}

    def isValid(self) -> bool:
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._timestamp) > 0 and len(self._input) > 0:
            return True
        return False

    def is_update_success(self) -> bool:
        """
        Metodo que retorna True si no se ha actualizado el valor por defecto de success

        :return:
        """
        if self._success != -1:
            return True
        return False
