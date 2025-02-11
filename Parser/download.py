#!/bin/env python3
# -*- coding: utf-8 -*-

from typing import NoReturn


class Download(object):
    """
    Clase download, tiene informacion de una descarga realizada por la sesion
    """

    def __init__(self, url: str, hash1: str, path: str, timestamp: str) -> NoReturn:
        """
        Constructor de clase

        :param url:
        :param hash1:
        :param path:
        :param timestamp:
        """
        self._url = url
        self._hash = hash1
        self._path = path
        self._timestamp = timestamp

    def get_url(self) -> str:
        """
        Metodo para obtener la url donde se encuentra el fichero

        :return:
        """
        return self._url

    def get_hash(self) -> str:
        """
        Metodo para obtener el hash del fichero

        :return:
        """
        return self._hash

    def get_path(self) -> str:
        """
        Metodo para obtener la ruta donde esta guardado el fichero

        :return:
        """
        return self._path

    def get_timestamp(self) -> str:
        """
        Metodo para obtener el tiemstamp de la descarga del fichero

        :return:
        """
        return self._timestamp

    def to_string(self) -> str:
        """
        Metodo para imprimir los valores de la clase

        :return:
        """
        return 'url: {}\n\tsha-256: {}\n\truta: {}'.format(self._url, self._hash, self._path)
