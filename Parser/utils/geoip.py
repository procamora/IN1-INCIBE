#!/bin/env python3
# -*- coding: utf-8 -*-

from typing import Union, Dict, Any

import geoip2.database
from geoip2.errors import AddressNotFoundError


def setIpInfo(ip) -> Union[Dict[str, Any], None]:
    """
    Metodo que obtiene de la base de datos toda la informacion geografica de la ip

    :return:
    """
    geoip2DB = geoip2.database.Reader('../GeoLite2-City.mmdb')

    try:
        response = geoip2DB.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return None

    if response.location.latitude is None:
        lat = 0
    else:
        lat = float(response.location.latitude)
    if response.location.longitude is None:
        lon = 0
    else:
        lon = float(response.location.longitude)

    # no uso este return, pero no lo borro por si en el futuro lo uso como funcion externa
    responseDict = {
        'continentName': response.continent.name,
        'continentCode': response.continent.code,
        'countryName': response.country.name,
        'countryCode': response.country.iso_code,
        'cityName': response.city.name,
        'postalCode': response.postal.code,
        'latitude': lat,
        'longitude': lon,
        'location': '{lat},{lon}'.format(lat=response.location.latitude, lon=response.location.longitude)
    }

    geoip2DB.close()

    return responseDict


if __name__ == "__main__":
    # print(setIpInfo('109.248.9.102'))
    # print(setIpInfo('157.100.133.21'))
    # print(setIpInfo('192.168.1.15'))
    # print(setIpInfo('211.90.1.201'))
    print(setIpInfo('151.217.178.88'))
