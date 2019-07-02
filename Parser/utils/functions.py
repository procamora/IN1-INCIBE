#!/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import re
from http import HTTPStatus  # https://docs.python.org/3/library/http.html

import colorlog  # https://medium.com/@galea/python-logging-example-with-color-formatting-file-handlers-6ee21d363184
import requests
from filehash import FileHash

requests.packages.urllib3.disable_warnings()


def getLogger(verbose, name='Parser'):
    # Desabilita log de modulos
    # for _ in ("boto", "elasticsearch", "urllib3"):
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


def is_downloadable(url):
    """
    Does the url contain a downloadable resource
    """
    try:
        h = requests.head(url, allow_redirects=True, verify=False)
        header = h.headers
        content_type = header.get('content-type')
        # if 'text' in content_type.lower():
        #    return False
        if content_type is not None and 'html' in content_type.lower():
            return False
        return True
    except Exception as e:
        l = getLogger(False)
        l.warning('not is_downloadable: {}'.format(url))
        return False


def get_shasum(file_url) -> str:
    # Si no tiene http:// requests falla al descargar
    if not re.search('http://', file_url):
        file_url = 'http://{}'.format(file_url)

    if is_downloadable(file_url):
        file_name = 'kk.bin'
        r = requests.get(file_url, verify=False)
        if r.status_code == HTTPStatus.OK:
            # Copiamos los ficheros por bloques
            with open(file_name, 'wb') as pdf:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        pdf.write(chunk)

            md5hasher = FileHash('sha256')
            newHash = md5hasher.hash_file("./{}".format(file_name))
            os.remove(file_name)  # FIXME DESCOMENTAR
            return newHash
        return None
    return None
