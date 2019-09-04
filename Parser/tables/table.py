#!/bin/env python3
# -*- coding: utf-8 -*-

import json
from abc import ABC, abstractmethod
from typing import NoReturn, Dict, Any


class Table(ABC, json.JSONEncoder):
    """
    Clase padre que contiene los metodos basicos que contienen todas las clases Tabla
    """

    def __init__(self) -> NoReturn:
        self._DEFAULT_VALUE = 'unknown'

    def to_json(self) -> Dict[str, Any]:
        """
        Metodo que generar un string con la serializacion de la clase en formato JSON

        :return:
        """
        # return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
        return json.dumps(self.__getstate__())

    @abstractmethod
    def __getstate__(self) -> Dict[str, Any]:
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """

    @abstractmethod
    def is_valid(self) -> bool:
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios
        :return: bool
        """
