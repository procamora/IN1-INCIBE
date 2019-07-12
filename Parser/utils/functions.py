#!/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import os
import re
import subprocess
from typing import Union, NoReturn

import colorlog  # https://medium.com/@galea/python-logging-example-with-color-formatting-file-handlers-6ee21d363184
import requests

requests.packages.urllib3.disable_warnings()


def get_logger(verbose: bool, name: str = 'Parser') -> colorlog:
    # Desabilita log de modulos
    # for _ in ("boto", "elasticsearch", "urllib3"):
    #    logging.getLogger(_).setLevel(logging.CRITICAL)

    log_format = '%(levelname)s - %(module)s - %(message)s'

    bold_seq = '\033[1m'
    colorlog_format = (
        f'{bold_seq} '
        '%(log_color)s '
        f'{log_format}'
    )

    colorlog.basicConfig(format=colorlog_format)
    # logging.basicConfig(format=colorlog_format)
    log = logging.getLogger(name)

    if verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    return log


def parser_date_time(line: str) -> str:
    """
    Metodo para obtener la fecha y hora de cualquier linea, si hay una T como separador entre la fecha y la hora ls
    sustituyo por un espacio en blanco y retorno solo la fecha hora, quitando las fracciones de segungo y zona horaria
    YYYY-MM-DD'T'HH:mm:ssZ

    :param line:
    :return:
    """
    regex_datetime = r'\d{4}-\d{2}-\d{2}(T| )\d{2}:\d{2}:\d{2}\.\d+(\+\d+|\w)'
    datetime = re.search(regex_datetime, line).group(0)
    return datetime.replace('T', ' ').split('.')[0]


def get_session(line) -> str:
    """
    Metodo para obtener la sesion. Esta unicamente en la linea New connection

    :param line:
    :return:
    """
    regex = r'session: (\w+)'
    return re.search(regex, line).group(1)


def parser_ip(line) -> str:
    """
    Metodo para obtener la ip. funciona unicamente en la linea New connection

    :param line:
    :return:
    """
    regex = r'New connection: (\d+.\d+.\d+.\d+)'
    return re.search(regex, line).group(1)


def parser_ip_any_line(line) -> str:
    """
    Metodo para obtener la ip de cualquier linea

    :param line:
    :return:
    """
    regex = r'.*\[.*,\d+,(\d+.\d+.\d+.\d+)\].*'
    return re.search(regex, line).group(1)


def parser_id_to_session(line) -> str:
    """
    Metodo para obtener el id de una conexion, este id junto a la ip identifican los log de una sesion

    :param line:
    :return:
    """
    regex = r'.*\[.*,(\d+),\d+.\d+.\d+.\d+\].*'
    return re.search(regex, line).group(1)


def parser_id_ip(line) -> Union[str, None]:
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


def write_file(text: str, fout: str, mode: str) -> NoReturn:
    """
    Metodo para escribir todos los INSERT INTO en un fichero

    :param text:
    :param fout:
    :param mode:
    :return:
    """
    with open(fout, mode) as fp:
        fp.write(text)


def check_dir(directory: str) -> NoReturn:
    """
    Metodo que comprueeba si existe un directorio, si no existe lo crea
    :param directory:
    :return:
    """
    if not os.path.isdir(directory):
        os.mkdir(directory)


def get_number_lines_file(file: str, loggers: logging) -> int:
    try:
        command = f'wc -l {file} | cut -d " " -f1'
        execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = execute.communicate()
        count_lines = int(stdout)
        print(count_lines)
        return count_lines
    except Exception as e:
        loggers.warning(e)
        loggers.warning('Method readlines')
        with open(file, 'r') as fp:
            count_lines = len(fp.readlines())
        return count_lines


def malware_get_reputation_ip(ip: str, loggers: logging) -> int:
    """
    Metodo para reguntar por la reputacion de una ip, te devuelve el numero de ataques que se han recibido de esa ip
    o -2 en caso de no recibir ninguno y -1 si falla la precion
    :param ip:
    :param loggers:
    :return:
    """
    URL = "http://127.0.0.1:8080"
    url = f'{URL}/getReputationIp?ip={ip}'
    headers = {'Accept': 'application/json'}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            # try:
            return json.loads(r.text)['reputation']
        # except json.decoder.JSONDecodeError:
        else:
            return -1
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        # print(f"No se ha podido comprobar la reputacion para {ip}")  # no se tiene acceso a logger
        loggers.warning(f"No se ha podido comprobar la reputacion para {ip}")  # fixme traducir
        return -1
