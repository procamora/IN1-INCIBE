#!/bin/env python3
# -*- coding: utf-8 -*-

import geoip2.database
from geoip2.errors import AddressNotFoundError

from .table import Table


class TableGeoIp(Table):
    """
    Clase que contiene los campos de la tabla ipinfo
    """

    def __init__(self, geoip2DB):
        """
        Constructor de clase
        """
        super().__init__()
        self._geoip2DB = geoip2DB
        self._ip = str()
        self._continentName = self._DEFAULT_VALUE
        self._continentCode = self._DEFAULT_VALUE
        self._countryName = self._DEFAULT_VALUE
        self._countryCode = self._DEFAULT_VALUE
        self._cityName = self._DEFAULT_VALUE
        self._postalCode = self._DEFAULT_VALUE
        self._location = '0,0'

    def setIp(self, ip):
        """
        Metedo establece la ip y obtiene la informacion geografica

        :param ip:
        :return:
        """
        if len(ip) > 0:
            self._ip = ip
            self.loadGeoIp()

    def loadGeoIp(self):
        """
        Metodo que obtiene de la base de datos toda la informacion geografica de la ip

        :return:
        """

        if self._geoip2DB is None:  # Este caso solo se da cuando se carga la clase desde un json y se tiene esta info
            return

        try:
            response = self._geoip2DB.city(self._ip)
        except geoip2.errors.AddressNotFoundError:
            return None

        if response.continent.name:
            self._continentName = response.continent.name
        if response.continent.code:
            self._continentCode = response.continent.code
        if response.country.name:
            self._countryName = response.country.name
        if response.country.iso_code:
            self._countryCode = response.country.iso_code
        if response.city.name:
            self._cityName = response.city.name
        if response.postal.code:
            self._postalCode = response.postal.code

        if response.location.latitude is not None and response.location.longitude is not None:
            self._location = '{lat},{lon}'.format(lat=response.location.latitude, lon=response.location.longitude)

    def loadGeoIpExtended(self, continentName, continentCode, countryName, countryCode, cityName, postalCode, location):
        if len(continentName) > 0:
            self._continentName = continentName
            self._continentCode = continentCode
            self._countryName = countryName
            self._countryCode = countryCode
            self._cityName = cityName
            self._postalCode = postalCode
            self._location = location

    def __getstate__(self):
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """

        return {'ip': self._ip, 'continentName': self._continentName, 'continentCode': self._continentCode,
                'countryName': self._countryName, 'countryCode': self._countryCode, 'cityName': self._cityName,
                'postalCode': self._postalCode, 'location': self._location, 'eventid': 'cowrie.session.geoip'}

    def isValid(self):
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._ip) > 0:
            return True
        return False
