#!/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import re

import colorlog  # https://medium.com/@galea/python-logging-example-with-color-formatting-file-handlers-6ee21d363184


def getLogger(verbose, name='Parser'):
    # Desabilita log de modulos
    #for _ in ("boto", "elasticsearch", "urllib3"):
    #    logging.getLogger(_).setLevel(logging.CRITICAL)

    logFormat = '%(levelname)s - %(module)s - %(message)s'

    bold_seq = '\033[1m'
    colorlog_format = (
        f'{bold_seq} '
        '%(log_color)s '
        f'{logFormat}'
    )

    colorlog.basicConfig(format=colorlog_format)
    # logging.basicConfig(format=colorlog_format)
    log = logging.getLogger(name)

    if verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    return log


def parserDateTime(line):
    """
    Metodo para obtener la fecha y hora de cualquier linea, si hay una T como separador entre la fecha y la hora ls
    sustituyo por un espacio en blanco y retorno solo la fecha hora, quitando las fracciones de segungo y zona horaria
    YYYY-MM-DD'T'HH:mm:ssZ

    :param line:
    :return:
    """
    regexDatetime = r'\d{4}-\d{2}-\d{2}(T| )\d{2}:\d{2}:\d{2}\.\d+(\+\d+|\w)'
    datetime = re.search(regexDatetime, line).group(0)
    return datetime.replace('T', ' ').split('.')[0]


def getSession(line):
    """
    Metodo para obtener la sesion. Esta unicamente en la linea New connection

    :param line:
    :return:
    """
    regex = r'session: (\w+)'
    return re.search(regex, line).group(1)


def parserIp(line):
    """
    Metodo para obtener la ip. funciona unicamente en la linea New connection

    :param line:
    :return:
    """
    regex = r'New connection: (\d+.\d+.\d+.\d+)'
    return re.search(regex, line).group(1)


def parserIpAnyLine(line):
    """
    Metodo para obtener la ip de cualquier linea

    :param line:
    :return:
    """
    regex = r'.*\[.*,\d+,(\d+.\d+.\d+.\d+)\].*'
    return re.search(regex, line).group(1)


def parserIdtoSession(line):
    """
    Metodo para obtener el id de una conexion, este id junto a la ip identifican los log de una sesion

    :param line:
    :return:
    """
    regex = r'.*\[.*,(\d+),\d+.\d+.\d+.\d+\].*'
    return re.search(regex, line).group(1)


def parserIdIp(line):
    """
    Metodo para obtener el id y la ip de una conexion

    :param line:
    :return:
    """
    regex = r'.*\[.*,(\d+,\d+.\d+.\d+.\d+)\].*'
    result = re.search(regex, line)
    if result is not None:
        return result.group(1)
    return None


def writeFile(text, fout, mode):
    """
    Metodo para escribir todos los INSERT INTO en un fichero

    :param text:
    :param fout:
    :param mode:
    :return:
    """
    with open(fout, mode) as fp:
        fp.write(text)


def checkDir(directory):
    """
    Metodo que comprueeba si existe un directorio, si no existe lo crea
    :param directory:
    :return:
    """
    if not os.path.isdir(directory):
        os.mkdir(directory)