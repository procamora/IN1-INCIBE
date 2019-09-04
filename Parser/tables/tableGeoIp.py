#!/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from typing import NoReturn, Dict, Any

import geoip2.database
from geoip2.errors import AddressNotFoundError

from .table import Table


@dataclass(order=True)
class TableGeoIp(Table):
    """
    Clase que contiene los campos de la tabla ipinfo
    """

    def __init__(self, geoip2_db: geoip2) -> NoReturn:
        """
        Constructor de clase
        """
        super().__init__()
        self._geoip2_db: geoip2 = geoip2_db
        self._ip: str = str()
        self._continent_name: str = self._DEFAULT_VALUE
        self._continent_code: str = self._DEFAULT_VALUE
        self._country_name: str = self._DEFAULT_VALUE
        self._country_code: str = self._DEFAULT_VALUE
        self._city_name: str = self._DEFAULT_VALUE
        self._postal_code: str = self._DEFAULT_VALUE
        self._location: str = '0,0'

    def set_ip(self, ip: str) -> NoReturn:
        """
        Metedo establece la ip y obtiene la informacion geografica

        :param ip:
        :return:
        """
        if len(ip) > 0:
            self._ip = ip
            self.load_geo_ip()

    def load_geo_ip(self) -> NoReturn:
        """
        Metodo que obtiene de la base de datos toda la informacion geografica de la ip

        :return:
        """

        if self._geoip2_db is None:  # Este caso solo se da cuando se carga la clase desde un json y se tiene esta info
            return

        try:
            response = self._geoip2_db.city(self._ip)
        except geoip2.errors.AddressNotFoundError:
            return None

        if response.continent.name:
            self._continent_name = response.continent.name
        if response.continent.code:
            self._continent_code = response.continent.code
        if response.country.name:
            self._country_name = response.country.name
        if response.country.iso_code:
            self._country_code = response.country.iso_code
        if response.city.name:
            self._city_name = response.city.name
        if response.postal.code:
            self._postal_code = response.postal.code

        if response.location.latitude is not None and response.location.longitude is not None:
            self._location = '{lat},{lon}'.format(lat=response.location.latitude, lon=response.location.longitude)

    def load_geo_ip_extended(self, continent_name: str, continent_code: str, country_name: str, country_code: str,
                             city_name: str, postal_code: str, location: str) -> NoReturn:
        if len(continent_name) > 0:
            self._continent_name = continent_name
            self._continent_code = continent_code
            self._country_name = country_name
            self._country_code = country_code
            self._city_name = city_name
            self._postal_code = postal_code
            self._location = location

    def __getstate__(self) -> Dict[str, Any]:
        """
        Redefino este metodo para generar los atributos que quiero serializar

        :return:
        """

        return {'ip': self._ip, 'continentName': self._continent_name, 'continentCode': self._continent_code,
                'countryName': self._country_name, 'countryCode': self._country_code, 'cityName': self._city_name,
                'postalCode': self._postal_code, 'location': self._location, 'eventid': 'cowrie.session.geoip'}

    def is_valid(self) -> bool:
        """
        Metodo que indica si esa clase es valida para generar el INSERT INTO, una clase es valida
        cuando ciertos atributos de la clase existen y no estan vacios

        :return: bool
        """
        if len(self._ip) > 0:
            return True
        return False
