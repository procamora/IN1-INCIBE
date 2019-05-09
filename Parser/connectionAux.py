#!/bin/env python3
# -*- coding: utf-8 -*-


class ConnectionAux(object):
    """
    Clase que contiene la informacion que se obtiene en la linea de New Connection
    """

    def __init__(self, ip, session, starttime):
        """
        Constructor de clase

        :param ip:
        :param session:
        :param starttime:
        """
        self._ip = ip
        self._pid = int()
        self._session = session
        self._starttime = starttime

    def getIp(self):
        """
        Metodo para obtener la ip de la conexion

        :return:
        """
        return self._ip

    def getId(self):
        """
        Metodo que rotorna el id,ip de la conexion

        :return:
        """
        return "{},{}".format(self._pid, self._ip)

    def setId(self, pid):
        """
        Metodo para establecer el id de la conexion

        :param pid:
        :return:
        """
        self._pid = pid

    def getSession(self):
        """
        Metodo para obtener la session de la conexion

        :return:
        """
        return self._session

    def getStarttime(self):
        """
        Metodo para obtener la fecha y hora en la que se establece la conexion

        :return:
        """
        return self._starttime

    def toString(self):
        """
        Metodo para imprimir el valor de los atributos de la clase

        :return:
        """
        return "{} -> {}".format(self.getId(), self._session)
