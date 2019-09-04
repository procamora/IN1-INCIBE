#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import glob
import logging
import re
import traceback
from timeit import default_timer as timer
from typing import NoReturn, Dict

import geoip2.database

from connectionAux import ConnectionAux
from download import Download
from newConnection import NewConnection
from utils.functions import parser_ip, get_session, parser_date_time, parser_id_to_session, parser_id_ip, write_file, \
    parser_ip_any_line, check_dir


class Parser(object):
    """
    Clase Parser encargada de parsear los ficheros de log
    """

    def __init__(self, logger: logging, output: str, working_dir: str, my_config: str) -> NoReturn:
        """
        Constructor de clase

        :param logger: Instancia de logging
        :param output: Directorio donde se guardan los ficheros de salida
        :param working_dir: Directorio donde se encuentran los log a analizar
        """
        config = configparser.ConfigParser()
        config.sections()
        config.read('settings.conf')

        check_dir(output)

        self._logger = logger
        self._log_completed = '{}/{}'.format(output, config[my_config]['FILE_LOG_COMPLETED'])
        self._log_aux_session = '{}/{}'.format(output, config[my_config]['FILE_LOG_SESSION'])
        self._log_aux_no_session = '{}/{}'.format(output, config[my_config]['FILE_LOG_NOSESSION'])
        self._geoip2_db = None
        self._working_dir = working_dir

        self._connection_wget = list()  # conexiones que han ejecutado un wget y hay que enlazarlo con la respuesta
        self._listCommandWget = list()  # Comandos wget ejecutados

        # Creamos el fichero con los insert y si existe lo vacia
        with open(self._log_completed, 'w'):
            pass
        # Creamos el fichero con los insert y si existe lo vacia
        with open(self._log_aux_session, 'w'):
            pass
        # Creamos el fichero con los insert y si existe lo vacia
        with open(self._log_aux_no_session, 'w'):
            pass

    def parse(self, db: str) -> NoReturn:
        """
        Metodo para arancar el proceso de parsear ficheros

        :return:
        """

        self._geoip2_db = geoip2.database.Reader(db)
        start_total = timer()
        for fname in sorted(glob.glob('{}/cowrie.log.*'.format(self._working_dir))):
            # for fname in sorted(glob.glob('{}/analizame.log'.format(self._workingDir))):
            self._logger.info('Analizando: {}'.format(fname))

            self._connection_wget.clear()  # Vaciamos la lista/diccionario porque no tiene informacion util en otro log
            self._listCommandWget.clear()

            # start = timer()
            try:
                connection_aux_dict = Parser.get_connections(fname)
                new_connection_dict = self.set_ip_to_id(connection_aux_dict, fname)
                self.get_info_log(new_connection_dict, fname)
            except UnicodeDecodeError as error:
                self._logger.error('Unicode decode error in file: {}'.format(fname))
                self._logger.debug(traceback.print_tb(error.__traceback__))
            # end = timer()
            # self._logger.debug('Time file: {}'.format(end - start))  # Time in seconds

        end_total = timer()
        self._logger.info('Time total: {} seg'.format(end_total - start_total))  # Time in seconds, e.g. 5.38091952400
        self._geoip2_db.close()

    @staticmethod
    def get_connections(fname: str) -> Dict[int, ConnectionAux]:
        """
        Metodo inicial que busca todas las New Connection que hay en el fichero y las asocia a la linea en la que estan

        :param fname:
        :return: Map<int, ConnectionAux>
        """
        connection_aux_dict = dict()  # asociacion de linea de la primera conexion con id session
        with open(fname, 'r') as fp:
            for numLine, line in enumerate(fp):
                # evitamos errores por lineas en blanco
                if re.match(r'.*New connection:.*', line, re.IGNORECASE) and \
                        re.match(r'.*session: (\w+).*', line, re.IGNORECASE):
                    connection_aux = ConnectionAux(parser_ip(line), get_session(line), parser_date_time(line))
                    connection_aux_dict[numLine + 1] = connection_aux  # Linea en la que estara la _ip con el id

        return connection_aux_dict

    def set_ip_to_id(self, connection_aux_dict: dict, fname: str) -> Dict[str, NewConnection]:
        """
        Asociamos una IP a su ID que lo identificara en cada una de las lineas del log [HoneyPotSSHTransport,id,ip]
        Devolvemos una lista de conexiones con la informacion que necesitamos para obtener el resto de datos

        :param connection_aux_dict:
        :param fname:
        :return: Map<String ,newConnectionDict>
        """

        new_connection_dict = dict()

        # Leemos el fichero y lo guardamos en un array por lineas
        with open(fname, 'r') as fp:
            file = fp.readlines()

        file_size = len(file)  # Comprobar que no superamos el array

        # Para cada conexion que tenemos buscamos cual es la primera linea que tiene su ip con el id
        for connection in connection_aux_dict:
            valid = True  # Condicion que se modifica si no se lleva al final del fichero sin encontrar una asociacion
            cont = connection
            s = str()
            if cont < file_size:  # si la linea esta en la ultima linea no buscamos mas
                s = file[cont]
            else:
                valid = False

            # Avanzamos las lineas necesarias hasta tener una linea con la ip de la conexion
            while valid and not re.match(r'.*,\d+,{}'.format(connection_aux_dict[connection].get_ip()), s,
                                         re.IGNORECASE):
                cont += 1
                if cont < file_size:
                    s = file[cont]
                else:
                    self._logger.warning(
                        'No puedo con: {} en linea: {}'.format(connection_aux_dict[connection].get_ip(), connection))
                    valid = False

            if valid:
                connection_aux_dict[connection].set_id(parser_id_to_session(s))  # Establecemos el id de la conexion
                if connection_aux_dict[connection].get_id() in new_connection_dict:
                    pass  # Posteriores conexiones con la misma id,ip los omitimos porque iran al objeto ya creado
                else:
                    new_connection_dict[connection_aux_dict[connection].get_id()] = NewConnection(
                        connection_aux_dict[connection], self._logger, self._geoip2_db)

        return new_connection_dict

    def get_info_log(self, new_connection_dict: dict, fname: str) -> NoReturn:
        """
        Metodo que recorre el fichero linea a linea y si existe el indice id,ip en el diccionario obtiene ek objeto
        asociado a ese indice y le añade esa linea, que solo guardara si tiene informacion util

        :param new_connection_dict:
        :param fname:
        :return:
        """

        with open(fname, 'r') as fp:
            for line in fp:
                info = parser_id_ip(line)
                if info is not None:
                    if info in new_connection_dict:  # Las lineas que tenemos en el diccionario las parseamos
                        new_connection_dict[info].add_line(line)
                        if re.match(r'.*CMD:.*wget.*', line, re.IGNORECASE):
                            self._connection_wget.append(info)  # si la linea contiene un wget guardo esa conexion
                    else:  # Lineas con id,ip pero que no tienen New connection y no estan en el diccionario
                        con_aux = ConnectionAux(parser_ip_any_line(line), '', '')
                        con_aux.set_id(parser_id_to_session(line))
                        new_connection_dict[info] = NewConnection(con_aux, self._logger, self._geoip2_db)
                        new_connection_dict[info].add_line(line)
                else:  # Lineas que no tienen id,ip
                    # Añadimos al fichero auxiliar de lineas no tratadas todas las lineas que no tengan la id,ip en el
                    # el diccionario y que no sean una New connection ya que estan ya han sido tratadas
                    if not re.match(r'.*New connection:.*', line, re.IGNORECASE) and len(line) > 2:
                        regex = r'^.*Downloaded URL \(b?\'(.*)\'\) with SHA-\d+ (\w+) to (.*)$'
                        if re.match(regex, line, re.IGNORECASE):
                            d = re.search(regex, line, re.IGNORECASE)
                            download = Download(d.group(1), d.group(2), d.group(3), parser_date_time(line))
                            self._listCommandWget.append(download)

        self.update_command_connection(new_connection_dict)

        for conect in new_connection_dict.values():
            if conect.is_completed():
                write_file(conect.get_json(), self._log_completed, 'a')
            elif conect.is_session():
                write_file(conect.get_json(), self._log_aux_session, 'a')
            else:
                write_file(conect.get_json(), self._log_aux_no_session, 'a')

    def search_wget(self, new_connection_dict: dict, command: Download) -> NoReturn:
        """
        Metodo que recorre la lista de conexiones que han ejecutado un comand wget, si el comando corresponde con
        el que estamos tratando le actualiza los valores y lo borra de la lista

        :param new_connection_dict:
        :param command:
        :return:
        """
        for connection in self._connection_wget:
            if new_connection_dict[connection].check_command_pending(command):
                self._connection_wget.remove(connection)
                return

    def update_command_connection(self, new_connection_dict: dict) -> NoReturn:
        """
        Metodo que recorre todos los comandos  wget ejecutados para comprobar si en el diccionario de conexiones se ha
        ejecutado

        :param new_connection_dict:
        :return:
        """
        # Aqui tenemos que recorrer cada comando y comprobar si tiene una wget pendiente de obtener un valor
        for command in self._listCommandWget:
            # self._logger.info(command.toString())
            self.search_wget(new_connection_dict, command)
