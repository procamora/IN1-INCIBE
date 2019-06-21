#!/bin/env python3
# -*- coding: utf-8 -*-

from .table import Table


class TableSessions(Table):
    """
    Clase que contiene los campos de la tabla Sessions
    """

    def __init__(self):
        """
        Constructor de clase
        """
        super().__init__()
        self._starttime = str()
        self._endtime = str()
        self._ip = str()
        self._termsize = self._DEFAULT_VALUE

    def setEndtime(self, endtime):
        """
        Metodo para establecer la fecha y hora de desconexion de la sesion

        :param endtime:
        :return:
        """
        if len(endtime) > 0:
            self._endtime = endtime

    def getEndtime(self):
        return self._endtime

    def setTermsize(self, termsize):
        """
        Metodo para estabecer el tamaño de la terminar

        :param termsize:
        :return:
        """
        if len(termsize) > 0 and termsize != self._DEFAULT_VALUE:
            self._termsize = termsize

    def load(self, starttime, ip):
        """
        Metedo que carga los principales valores de la tabla

        :param starttime:
        :param ip:
        :return:
        """
        if len(starttime) > 0:
            self._starttime = starttime
        if len(ip) > 0:
            self._ip = ip

    def __getstate__(self):
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """
        return {'starttime': self._starttime, 'endtime': self._endtime, 'ip': self._ip, 'termsize': self._termsize,
                'eventid': 'cowrie.session'}

    def isValid(self):
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._starttime) > 0 and len(self._endtime) > 0 and len(self._ip) > 0:
            return True
        return False
