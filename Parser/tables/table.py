#!/bin/env python3
# -*- coding: utf-8 -*-

import json


class Table(json.JSONEncoder):
    """
    Clase padre que contiene los metodos basicos que contienen todas las clases Tabla
    """

    def __init__(self):
        self._DEFAULT_VALUE = 'unknown'

    def toJSON(self):
        """
        Metodo que generar un string con la serializacion de la clase en formato JSON

        :return:
        """
        # return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
        return json.dumps(self.__getstate__())

    def __getstate__(self):
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        pass

    def isValid(self):
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios
        :return: bool
        """
        pass
