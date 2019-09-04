#!/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import annotations

import json
import logging
import re
from typing import NoReturn, List, Union
import geoip2

from connectionAux import ConnectionAux
from objectEncoder import ObjectEncoder
from tables import *
from threatLevel import ThreatLevel
from utils.functions import parser_date_time, malware_get_reputation_ip
from download import Download


class NewConnection(json.JSONEncoder):
    """
    Clase que contiene toda la informacion almacenada en el log de una NewConection
    """

    def __init__(self, connection_aux: ConnectionAux, logger: logging, geoip2_db: Union[geoip2, None]) -> NoReturn:
        """
        Constructor de clase

        :param connection_aux:
        :param logger:
        :param geoip2_db:
        """
        self._IdSession = connection_aux.get_session()
        self._idip = connection_aux.get_id()
        self._threatLevel = int()  # Leve 1 Media 2 Alta 3
        self._isScanPort = bool()
        self._isBruteForceAttack = bool()
        self._reputation = -1
        self._connectionAux = connection_aux
        self._logger = logger
        self._listCommandPending = list()

        self._client = TableClients()
        # self._tableSensors = TableSensors()
        self._ttylog = TableTtylog()
        self._session = TableSessions()
        self._geoip = TableGeoIp(geoip2_db)
        self._fingerprint = TableFingerprint()
        self._eventid = 'cowrie.extend'

        self._listInputs = list()
        self._listAuths = list()
        self._listDownloads = list()

        # Establecemos algunos valores de session
        self._session.load(self._connectionAux.get_starttime(), self._connectionAux.get_ip())
        self._geoip.set_ip(self._connectionAux.get_ip())

    def getId(self) -> str:
        """
        Metodo para obtener la id.ip de la conexion

        :return:
        """
        return self._connectionAux.get_id()

    def check_command_pending(self, command: Download) -> bool:
        """
        Metodo que retorna True si el comando wget que recibe esta pendiente de comprobar, si esta pendiente lo borra
        de la lista de comandos pendientes y lo añade a la lista de descargas

        :param command:
        :return:
        """
        if len(self._listCommandPending) == 0:
            return False

        for i in self._listCommandPending:
            if command.get_url() == i:
                # print("EXITO")
                d = TableDownloads(command.get_timestamp(), command.get_url(), command.get_path(), command.get_hash())
                self._listDownloads.append(d)
                self._listCommandPending.remove(i)
                return True

        return False

    def add_line(self, line: str) -> bool:
        """
        Metodo para analizar una linea, comprueba si la linea coincide con alguna de las regex, si coincide guardara esa
        informacion en la tabla asociada a esa informacion

        :param line:
        :return:
        """
        # UPDATE CLIENTS
        regex = r'^.*Remote SSH version: b?\'?(.*)\'?$'
        if re.match(regex, line):
            client = re.search(regex, line).group(1)

            # ocurre por el \'?$ de la regex, este caso no se daria si solo tuviese un formato
            if len(client) > 0 and client[-1] == '\'':
                client = client[0:-1]

            regex = r'^SSH-\d\.\d(-|_)([a-z0-9]+)(((_|-)(release|snapshot))?(\/|-|\.|_)(\d+.?)+)?'
            # Si es un cliente SSH-2.0 que cumple la regex unicamente dejo el nombre del cliente
            if re.match(regex, client, re.IGNORECASE):
                name_client = re.search(regex, client, re.IGNORECASE).group(2)
                self._client.load(client, name_client)
            else:
                self._client.load(client, client)
                self._logger.debug(client)
            return True

        regex = r'^.*kex alg, key alg: b?\'(.*)\' b?\'(.*)\'$'
        if re.match(regex, line):
            key = re.search(regex, line)
            self._client.set_kex_alg(key.group(1))
            self._client.set_key_alg(key.group(2))

        regex = r'^.*incoming: b?\'(.*)\' b?\'(.*)\' b?\'(.*)\'.*$'
        if re.match(regex, line):
            key = re.search(regex, line)
            self._client.set_encryption(key.group(1))
            self._client.set_authentication(key.group(2))

        # UPDATE TTYLOG
        regex = r'.*Closing TTY Log: (.*) after \d+ \w+'
        if re.match(regex, line):
            self._ttylog.set_ttylog(re.search(regex, line).group(1))
            return True

        # UPDATE SESSIONS
        regex = r'.*Terminal Size: (\d+ \d+)'
        if re.match(regex, line):
            self._session.set_termsize(re.search(regex, line).group(1).replace(' ', 'x'))
            return True

        regex = r'.*Connection lost after \d+ seconds'
        if re.match(regex, line):
            self._session.set_endtime(parser_date_time(line))
            return True

        # UPDATE AUTH
        regex = r'^.*login attempt \[(b\')?(\w+)(\')?\/(b\')?(\w+)(\')?\] (succeeded|failed)$'
        if re.match(regex, line):
            table_auth = TableAuth()
            if re.search(regex, line).group(7) == "succeeded":
                success = 1
            else:
                success = 0

            table_auth.load(success, re.search(regex, line).group(2),
                           re.search(regex, line).group(5), parser_date_time(line))
            self._listAuths.append(table_auth)
            return True

        # UPDATE INPUT
        regex = r'.*CMD: (.*)'
        if re.match(regex, line):
            # Se crea una tabla por cada comando, si estan en bloque se parten
            execute_command = re.search(regex, line).group(1)
            for command in NewConnection.getListCommands(execute_command):
                table_input = TableInput()
                table_input.load(parser_date_time(line), command)
                self._listInputs.append(table_input)
                regex = r".*wget ((?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:\/?#[\]@!\$&'\(\)\*\+,;=.\%]+).*"
                if re.match(regex, command):
                    self._logger.debug('Ejecuto comando: wget {}'.format(re.search(regex, command).group(1)))
                    self._listCommandPending.append(re.search(regex, command).group(1))
                    # cowrie.log.2018-12-05
                    # CMD: cd /tmp; wget google.com
                    # Downloaded URL (b'http://google.com')
            return True

        regex = r'.*Command( not)? found: (.*)'
        if re.match(regex, line):
            cmd = re.search(regex, line).group(2).strip()
            for i in self._listInputs:
                # Comprobamos que el comando sea el mismo y que no este puesto el resultado de la ejecucion
                if i.get_input() == cmd and not i.is_update_success():
                    regex = r'.*Command( not)? found: ({})'.format(re.escape(cmd))  # Escapamos el comand para la regex
                    if NewConnection.isCommandFound(line, regex):
                        i.set_success(1)
                    else:
                        i.set_success(0)
            return True

        # UPDATE KEYFINGERPRINTS
        regex = r'.*fingerprint:? ((\w{2}:?){16}).*'
        if re.match(regex, line):
            # user = re.search(r'.*user b\'(\w+)\'.*', line).group(1)  # Esta en alguna version
            self._fingerprint.set_fingerprint(re.search(regex, line).group(1))
            return True

        return False

    def update_atributes(self) -> NoReturn:
        """
        Metodo para actualizar los atributos de clasificacion de la sesion
        Comprobamos si la sesion es un scaneo o un ataque de fuerza bruta

        :return:
        """
        if len(self._listAuths) == 0:
            self._isScanPort = True
        else:
            self._isScanPort = False

        if len(self._listAuths) > 2:
            self._isBruteForceAttack = True
        else:
            self._isBruteForceAttack = False

    def get_json(self) -> str:
        """
        Metodo para obtener un string con toda la informacion de la conexion en formato JSON

        :return: string
        """

        # self.updateThreatLevel()
        threat_level = ThreatLevel()
        self._threatLevel = threat_level.get_threat_level(self._listInputs)

        self.update_atributes()

        # Creo un diccionario solo con los valores que necesito y elimminando el _ de las variables privadas
        my_dict = dict()
        ignore = ['_connectionAux', '_logger', '_listCommandPending', '_COMMANDS_DANGEROUS']
        for i in self.__dict__:
            if i not in ignore:
                my_dict[i.replace('_', '')] = self.__dict__[i]

        return '{}\n'.format(json.dumps(my_dict, cls=ObjectEncoder))

    def get_json_cowrie(self, logger: logging, dict_reputation_ip: dict) -> str:
        """
        Metodo para obtener un string con toda la informacion de la conexion en formato JSON

        :return: string
        """
        # self.updateThreatLevel()
        threat_level = ThreatLevel()
        self._threatLevel = threat_level.get_threat_level(self._listInputs)

        self.update_atributes()

        # Creo un diccionario solo con los valores que necesito y elimminando el _ de las variables privadas
        myDict = dict()
        ignore = ['_connectionAux', '_logger', '_listCommandPending', '_COMMANDS_DANGEROUS']
        for i in self.__dict__:
            if i not in ignore:
                myDict[i.replace('_', '')] = self.__dict__[i]

        my_json = str()
        extend_json = str()
        for i in myDict:
            # Si solo es una tabla lo converte a json y añande la sesion
            if isinstance(myDict[i], Table):
                if isinstance(myDict[i], TableSessions) and len(myDict[i].get_endtime()) == 0:
                    myDict[i].set_endtime(myDict[i].get_starttime())
                json_table = myDict[i].to_json()
                json_update = json.loads(json_table)
                json_update['session'] = self._IdSession
                my_json = "{}\n{}".format(my_json, json.dumps(json_update))
            # Si es una lista de tablas para cada una le añade la sesion y para comandos añade el binario
            elif isinstance(myDict[i], list):
                for j in myDict[i]:
                    json_table = j.to_json()
                    json_update = json.loads(json_table)
                    json_update['session'] = self._IdSession
                    if isinstance(j, TableInput):
                        json_update['binary'] = json_update['input'].split(' ')[0]
                    my_json = "{}\n{}".format(my_json, json.dumps(json_update))
            # Los elementos sueltos los añade a un unoco json
            else:
                if len(extend_json) == 0:
                    extend_json = "{\"%s\": \"%s\"" % (i, myDict[i])
                else:
                    extend_json = "{}, \"{}\": \"{}\"".format(extend_json, i, myDict[i])

        extend_json = "%s}" % extend_json
        json_update = json.loads(extend_json)
        json_update['session'] = self._IdSession

        # primero miramos si la tenemos en el diccionario para evitar peticcion http
        if self._connectionAux.get_ip() in dict_reputation_ip:
            json_update['reputation'] = dict_reputation_ip[self._connectionAux.get_ip()]
        else:
            reput = malware_get_reputation_ip(self._connectionAux.get_ip(), logger)
            json_update['reputation'] = reput
            dict_reputation_ip[self._connectionAux.get_ip()] = reput

        json_update['isScanPort'] = json_update['isScanPort'].lower()  # elasticsearch usa booleanos en minusculas
        json_update['isBruteForceAttack'] = json_update['isBruteForceAttack'].lower()
        json_update.pop('IdSession', None)

        my_json = "{}\n{}".format(my_json, json.dumps(json_update))
        # return '{}\n'.format(json.dumps(myDict, cls=ObjectEncoder))
        return my_json

    def loadClient(self, string_json: dict) -> NoReturn:
        self._client.load(string_json['version'], string_json['shortName'])
        self._client.set_key_alg(string_json['keyAlg'])
        self._client.set_kex_alg(string_json['kexAlg'])
        self._client.set_encryption(string_json['encryption'])
        self._client.set_authentication(string_json['authentication'])

    def loadTtylog(self, string_json: dict) -> NoReturn:
        self._ttylog.set_ttylog(string_json['ttylog'])
        self._ttylog.set_size(string_json['size'])

    def loadSession(self, string_json: dict) -> NoReturn:
        self._session.load(string_json['starttime'], string_json['ip'])
        self._session.set_endtime(string_json['endtime'])
        self._session.set_termsize(string_json['termsize'])

    def loadGeoIp(self, string_json: dict) -> NoReturn:
        self._geoip.load_geo_ip_extended(string_json['continentName'], string_json['continentCode'],
                                         string_json['countryName'], string_json['countryCode'], string_json['cityName'],
                                         string_json['postalCode'], string_json['location'])

    def loadFingerprint(self, string_json: dict) -> NoReturn:
        self._fingerprint.set_fingerprint(string_json['fingerprint'])

    def loadInput(self, string_json: dict) -> NoReturn:
        t = TableInput()
        t.load(string_json['timestamp'], string_json['input'])
        t.set_success(string_json['success'])
        self._listInputs.append(t)

    def loadAuth(self, string_json: dict) -> NoReturn:
        a = TableAuth()
        a.load(string_json['success'], string_json['username'], string_json['password'], string_json['timestamp'])
        self._listAuths.append(a)

    def loadDownload(self, string_json: dict) -> NoReturn:
        d = TableDownloads(string_json['timestamp'], string_json['url'], string_json['outfile'], string_json['shasum'])
        self._listDownloads.append(d)

    def isCompleted(self) -> bool:
        """
        Metodo que indica si esta session esta completa

        :return:
        """
        if len(self._IdSession) > 1 and len(self._session.get_endtime()) > 1:
            return True
        return False

    def isSession(self) -> bool:
        """
        Metodo que indica si esta session tiene establecida una session o solo se puede identificar por id,ip

        :return:
        """
        if len(self._IdSession) > 1:
            return True
        return False

    @staticmethod
    def getListCommands(commands: str) -> List[str]:
        list_commands = list()
        # Casos especificos donde el comando lleva una regex
        if re.search(r'(grep -E)', commands):
            regex = r'(\;|\&+|\|{2})'
        else:
            regex = r'(\;|\&+|\|+)'

        for c in re.split(regex, commands):
            if not re.match(regex, c) and len(c) > 0:
                list_commands.append(c.strip())
        return list_commands

    @staticmethod
    def isCommandFound(line: str, regex: str) -> bool:
        """
        Metodo para comprobar si un comando se ha ejecutado con exito, avanza las lineas necesarias
        hasta llegar a la linea que indica si ha tenido exito la ejecucion del comando

        :param line:
        :param regex:
        :return:
        """
        if re.search(regex, line).group(1) is None:
            return True
        else:
            return False

    @staticmethod
    def fromJson(json_session: dict, json_no_session: dict, simple: bool = True) -> NewConnection:
        aux = ConnectionAux(json_session['session']['ip'], json_session['IdSession'], json_session['session']['starttime'])
        aux.set_id(json_session['idip'].split(',')[0])
        n_con = NewConnection(aux, False, None)

        for i in json_session:
            if i == 'client':
                n_con.loadClient(json_session[i])
                if simple:
                    n_con.loadClient(json_no_session[i])
            elif i == 'ttylog':
                n_con.loadTtylog(json_session[i])
                if simple:
                    n_con.loadTtylog(json_no_session[i])
            elif i == 'session':
                n_con.loadSession(json_session[i])
                if simple:
                    n_con.loadSession(json_no_session[i])
            elif i == 'geoip':
                n_con.loadGeoIp(json_session[i])
                if simple:
                    n_con.loadGeoIp(json_no_session[i])
            elif i == 'fingerprint':
                n_con.loadFingerprint(json_session[i])
                if simple:
                    n_con.loadFingerprint(json_no_session[i])
            elif i == 'listInputs':
                for command in json_session[i]:
                    n_con.loadInput(command)
                if simple:
                    for command in json_no_session[i]:
                        n_con.loadInput(command)
            elif i == 'listAuths':
                for auth in json_session[i]:
                    n_con.loadAuth(auth)
                if simple:
                    for auth in json_no_session[i]:
                        n_con.loadAuth(auth)
            elif i == 'listDownloads':
                for download in json_session[i]:
                    n_con.loadDownload(download)
                if simple:
                    for download in json_no_session[i]:
                        n_con.loadDownload(download)
        if simple:
            return n_con
        else:
            return n_con
