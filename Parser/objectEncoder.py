#!/bin/env python3
# -*- coding: utf-8 -*-
# Fuente: https://stackoverflow.com/questions/3768895/how-to-make-a-class-json-serializable

import inspect
import json
from typing import Dict, Any


class ObjectEncoder(json.JSONEncoder):
    """
    Clase para codificar una clase en un objeto JSON
    """

    def default(self, obj) -> Dict[str, Any]:
        """
        Metodo que se llama implicitamente cuando hacemos un dumps de una instancia de la clase, crea un diccionario
        de los atributos de la clase eliminando aquellos que no deben exportarse al json

        :param obj:
        :return:
        """
        if hasattr(obj, "__getstate__"):
            return self.default(obj.__getstate__())
        elif hasattr(obj, "__dict__"):
            d = dict(
                (key, value)
                for key, value in inspect.getmembers(obj)
                if not key.startswith("__")
                and not inspect.isabstract(value)
                and not inspect.isbuiltin(value)
                and not inspect.isfunction(value)
                and not inspect.isgenerator(value)
                and not inspect.isgeneratorfunction(value)
                and not inspect.ismethod(value)
                and not inspect.ismethoddescriptor(value)
                and not inspect.isroutine(value)
            )
            return self.default(d)
        return obj
