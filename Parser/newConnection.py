#!/bin/env python3
# -*- coding: utf-8 -*-


import json
import re

from connectionAux import ConnectionAux
from objectEncoder import ObjectEncoder
from tables import *
from threatLevel import ThreatLevel
from utils.functions import parserDateTime


class NewConnection(json.JSONEncoder):
    """
    Clase que contiene toda la informacion almacenada en el log de una NewConection
    """

    def __init__(self, connectionAux, logger, geoip2DB):
        """
        Constructor de clase

        :param connectionAux:
        :param logger:
        :param geoip2DB:
        """
        self._IdSession = connectionAux.getSession()
        self._idip = connectionAux.getId()
        self._threatLevel = int()  # Leve 1 Media 2 Alta 3
        self._isScanPort = bool()
        self._isBruteForceAttack = bool()
        self._connectionAux = connectionAux
        self._logger = logger
        self._listCommandPending = list()

        self._client = TableClients()
        # self._tableSensors = TableSensors()
        self._ttylog = TableTtylog()
        self._session = TableSessions()
        self._geoip = TableGeoIp(geoip2DB)
        self._fingerprint = TableFingerprint()
        self._eventid = 'cowrie.extend'

        self._listInputs = list()
        self._listAuths = list()
        self._listDownloads = list()

        # Establecemos algunos valores de session
        self._session.load(self._connectionAux.getStarttime(), self._connectionAux.getIp())
        self._geoip.setIp(self._connectionAux.getIp())

    def getId(self):
        """
        Metodo para obtener la id.ip de la conexion

        :return:
        """
        return self._connectionAux.getId()

    def checkCommandPending(self, command):
        """
        Metodo que retorna True si el comando wget que recibe esta pendiente de comprobar, si esta pendiente lo borra
        de la lista de comandos pendientes y lo añade a la lista de descargas

        :param command:
        :return:
        """
        if len(self._listCommandPending) == 0:
            return False

        for i in self._listCommandPending:
            if command.getUrl() == i:
                # print("EXITO")
                d = TableDownloads(command.getTimestamp(), command.getUrl(), command.getPath(), command.getHash())
                self._listDownloads.append(d)
                self._listCommandPending.remove(i)
                return True

        return False

    def addLine(self, line):
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
                nameClient = re.search(regex, client, re.IGNORECASE).group(2)
                self._client.load(client, nameClient)
            else:
                self._client.load(client, client)
                self._logger.debug(client)
            return True

        regex = r'^.*kex alg, key alg: b?\'(.*)\' b?\'(.*)\'$'
        if re.match(regex, line):
            key = re.search(regex, line)
            self._client.setKexAlg(key.group(1))
            self._client.setKeyAlg(key.group(2))

        regex = r'^.*incoming: b?\'(.*)\' b?\'(.*)\' b?\'(.*)\'.*$'
        if re.match(regex, line):
            key = re.search(regex, line)
            self._client.setEncryption(key.group(1))
            self._client.setAuthentication(key.group(2))

        # UPDATE TTYLOG
        regex = r'.*Closing TTY Log: (.*) after \d+ \w+'
        if re.match(regex, line):
            self._ttylog.setTtylog(re.search(regex, line).group(1))
            return True

        # UPDATE SESSIONS
        regex = r'.*Terminal Size: (\d+ \d+)'
        if re.match(regex, line):
            self._session.setTermsize(re.search(regex, line).group(1).replace(' ', 'x'))
            return True

        regex = r'.*Connection lost after \d+ seconds'
        if re.match(regex, line):
            self._session.setEndtime(parserDateTime(line))
            return True

        # UPDATE AUTH
        regex = r'^.*login attempt \[(b\')?(\w+)(\')?\/(b\')?(\w+)(\')?\] (succeeded|failed)$'
        if re.match(regex, line):
            tableAuth = TableAuth()
            if re.search(regex, line).group(7) == "succeeded":
                success = 1
            else:
                success = 0

            tableAuth.load(success, re.search(regex, line).group(2),
                           re.search(regex, line).group(5), parserDateTime(line))
            self._listAuths.append(tableAuth)
            return True

        # UPDATE INPUT
        regex = r'.*CMD: (.*)'
        if re.match(regex, line):
            # Se crea una tabla por cada comando, si estan en bloque se parten
            executeCommand = re.search(regex, line).group(1)
            for command in NewConnection.getListCommands(executeCommand):
                tableInput = TableInput()
                # regex = r'([a-zA-Z]+ \-[a-zA-Z]+)|([a-zA-Z]+ [0-9]{3})|([a-zA-Z]+ \/[a-zA-Z]+\/[a-zA-Z]+)|([a-zA-Z]+ )'
                # Acorta comandos ej: /gisdfoewrsfdf/bin
                regex = r'^(\/[a-zA-Z]+\/[a-zA-Z]+\/?)'
                # Acortamos a un solo directorio
                # regex1 = r'^(\/[a-zA-Z]+\/)'
                # Acorta comandos ej: cd /bin/bash/sh en cd /bin/bash/
                regex_1 = r'^([a-zA-Z]+\s\/[a-zA-Z]+\/?[A-Za-z]+\/?)'
                # Acortamos a un solo directorio
                # regex_1_1 = r'^([a-zA-Z]+\s\/[a-zA-Z]+\/?)'
                # Acorta el resto de comandos echo -e
                regex_2 = r'^([a-zA-Z]+\s(((\-[a-zA-Z]+)|([0-9]{3}(?!\.)))*))'
                #Acorta comando simple, exit, echo, ls, vi
                regex_3 = r'^[a-zA-Z]+'

                if re.match(regex_1, command):
                    # if len(re.search(regex_1_1, command).group(0)) == 0:
                    # print(command)
                    tableInput.load(parserDateTime(line), re.search(regex_1, command).group(0))
                    # print("."+re.search(regex_1_1, command).group(0)+"."+command)
                elif re.match(regex, command):
                    # if len(re.search(regex1, command).group(0)) == 0:
                    # print(command)
                    tableInput.load(parserDateTime(line), re.search(regex, command).group(0))
                    # print("."+re.search(regex1, command).group(0)+".")
                elif re.match(regex_2, command):
                    # if len(re.search(regex_2, command).group(0)) == 0:
                    # print(command)
                    tableInput.load(parserDateTime(line), re.search(regex_2, command).group(0))
                    # print("."+re.search(regex_2, command).group(0)+"."+command)
                elif re.match(regex_3,command):
                    # print(re.search(regex_3, command).group(0))
                    tableInput.load(parserDateTime(line), re.search(regex_3, command).group(0))
                # else:
                # tableInput.load(parserDateTime(line),command)
                self._listInputs.append(tableInput)
                regex = r".*wget ((?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:\/?#[\]@!\$&'\(\)\*\+,;=.\%]+).*"
                if re.match(regex, line):
                    self._logger.debug('Ejecuto comando: wget {}'.format(re.search(regex, line).group(1)))
                    self._listCommandPending.append(re.search(regex, line).group(1))
                    # cowrie.log.2018-12-05
                    # CMD: cd /tmp; wget google.com
                    # Downloaded URL (b'http://google.com')
            return True

        regex = r'.*Command( not)? found: (.*)'
        if re.match(regex, line):
            cmd = re.search(regex, line).group(2).strip()
            for i in self._listInputs:
                # Comprobamos que el comando sea el mismo y que no este puesto el resultado de la ejecucion
                if i.getInput() == cmd and not i.isUpdateSuccess():
                    regex = r'.*Command( not)? found: ({})'.format(re.escape(cmd))  # Escapamos el comand para la regex
                    if NewConnection.isCommandFound(line, regex):
                        i.setSuccess(1)
                    else:
                        i.setSuccess(0)
            return True

        # UPDATE KEYFINGERPRINTS
        regex = r'.*fingerprint:? ((\w{2}:?){16}).*'
        if re.match(regex, line):
            # user = re.search(r'.*user b\'(\w+)\'.*', line).group(1)  # Esta en alguna version
            self._fingerprint.setFingerprint(re.search(regex, line).group(1))
            return True

        return False

    def updateAtributes(self):
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

    def getJSON(self):
        """
        Metodo para obtener un string con toda la informacion de la conexion en formato JSON

        :return: string
        """

        # self.updateThreatLevel()
        threatLevel = ThreatLevel()
        self._threatLevel = threatLevel.getThreatLevel(self._listInputs)

        self.updateAtributes()

        # Creo un diccionario solo con los valores que necesito y elimminando el _ de las variables privadas
        myDict = dict()
        ignore = ['_connectionAux', '_logger', '_listCommandPending', '_COMMANDS_DANGEROUS']
        for i in self.__dict__:
            if i not in ignore:
                myDict[i.replace('_', '')] = self.__dict__[i]

        return '{}\n'.format(json.dumps(myDict, cls=ObjectEncoder))

    def getJSONCowrie(self):
        """
        Metodo para obtener un string con toda la informacion de la conexion en formato JSON

        :return: string
        """

        # self.updateThreatLevel()
        threatLevel = ThreatLevel()
        self._threatLevel = threatLevel.getThreatLevel(self._listInputs)

        self.updateAtributes()

        # Creo un diccionario solo con los valores que necesito y elimminando el _ de las variables privadas
        myDict = dict()
        ignore = ['_connectionAux', '_logger', '_listCommandPending', '_COMMANDS_DANGEROUS']
        for i in self.__dict__:
            if i not in ignore:
                myDict[i.replace('_', '')] = self.__dict__[i]

        myJson = str()
        extendJson = str()
        for i in myDict:
            # Si solo es una tabla lo converte a json y añande la sesion
            if isinstance(myDict[i], Table):
                if isinstance(myDict[i], TableSessions) and len(myDict[i].getEndtime()) == 0:
                    myDict[i].setEndtime(myDict[i].getStarttime())
                jsonTable = myDict[i].toJSON()
                jsonUpdate = json.loads(jsonTable)
                jsonUpdate['session'] = self._IdSession
                myJson = "{}\n{}".format(myJson, json.dumps(jsonUpdate))
            # Si es una lista de tablas para cada una le añade la sesion y para comandos añade el binario
            elif isinstance(myDict[i], list):
                for j in myDict[i]:
                    jsonTable = j.toJSON()
                    jsonUpdate = json.loads(jsonTable)
                    jsonUpdate['session'] = self._IdSession
                    if isinstance(j, TableInput):
                        jsonUpdate['binary'] = jsonUpdate['input'].split(' ')[0]
                    myJson = "{}\n{}".format(myJson, json.dumps(jsonUpdate))
            # Los elementos sueltos los añade a un unoco json
            else:
                if len(extendJson) == 0:
                    extendJson = "{\"%s\": \"%s\"" % (i, myDict[i])
                else:
                    extendJson = "{}, \"{}\": \"{}\"".format(extendJson, i, myDict[i])

        extendJson = "%s}" % extendJson
        jsonUpdate = json.loads(extendJson)
        jsonUpdate['session'] = self._IdSession
        # elasticsearch usa booleanos en minusculas
        jsonUpdate['isScanPort'] = jsonUpdate['isScanPort'].lower()
        jsonUpdate['isBruteForceAttack'] = jsonUpdate['isBruteForceAttack'].lower()
        jsonUpdate.pop('IdSession', None)

        myJson = "{}\n{}".format(myJson, json.dumps(jsonUpdate))
        # return '{}\n'.format(json.dumps(myDict, cls=ObjectEncoder))
        return myJson

    def loadClient(self, stringJson):
        self._client.load(stringJson['version'], stringJson['shortName'])
        self._client.setKeyAlg(stringJson['keyAlg'])
        self._client.setKexAlg(stringJson['kexAlg'])
        self._client.setEncryption(stringJson['encryption'])
        self._client.setAuthentication(stringJson['authentication'])

    def loadTtylog(self, stringJson):
        self._ttylog.setTtylog(stringJson['ttylog'])
        self._ttylog.setSize(stringJson['size'])

    def loadSession(self, stringJson):
        self._session.load(stringJson['starttime'], stringJson['ip'])
        self._session.setEndtime(stringJson['endtime'])
        self._session.setTermsize(stringJson['termsize'])

    def loadGeoIp(self, stringJson):
        self._geoip.loadGeoIpExtended(stringJson['continentName'], stringJson['continentCode'],
                                      stringJson['countryName'], stringJson['countryCode'], stringJson['cityName'],
                                      stringJson['postalCode'], stringJson['location'])

    def loadFingerprint(self, stringJson):
        self._fingerprint.setFingerprint(stringJson['fingerprint'])

    def loadInput(self, stringJson):
        t = TableInput()
        t.load(stringJson['timestamp'], stringJson['input'])
        t.setSuccess(stringJson['success'])
        self._listInputs.append(t)

    def loadAuth(self, stringJson):
        a = TableAuth()
        a.load(stringJson['success'], stringJson['username'], stringJson['password'], stringJson['timestamp'])
        self._listAuths.append(a)

    def loadDownload(self, stringJson):
        d = TableDownloads(stringJson['timestamp'], stringJson['url'], stringJson['outfile'], stringJson['shasum'])
        self._listDownloads.append(d)

    def isCompleted(self):
        """
        Metodo que indica si esta session esta completa

        :return:
        """
        if len(self._IdSession) > 1 and len(self._session.getEndtime()) > 1:
            return True
        return False

    def isSession(self):
        """
        Metodo que indica si esta session tiene establecida una session o solo se puede identificar por id,ip

        :return:
        """
        if len(self._IdSession) > 1:
            return True
        return False

    @staticmethod
    def getListCommands(commands):
        listCommands = list()
        regex = r'(\;|\&+|\|{2})'
        for c in re.split(regex, commands):
            if not re.match(regex, c) and len(c) > 0:
                listCommands.append(c.strip())
        return listCommands

    @staticmethod
    def getListCommandsSeparate(commands):
        """
        Metodo utilizado para generar vectores de ML y parsear líneas de comandos en comandos simples.
        No se eliminan las opciones introducidas al comando (primera prueba)

        :param commands:
        :return:
        """
        listCommands = list()
        regex = r'\;|\&+|\|+ '
        regex1 = r' '
        for c in re.split(regex, commands):
            if not re.match(regex, c) and re.match(regex1, c) and len(c) > 0:
                listCommands.append(c.strip())
        return listCommands

    @staticmethod
    def isCommandFound(line, regex):
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
    def fromJson(jsonSession, jsonNoSession, simple=True):
        aux = ConnectionAux(jsonSession['session']['ip'], jsonSession['IdSession'], jsonSession['session']['starttime'])
        aux.setId(jsonSession['idip'].split(',')[0])
        nCon = NewConnection(aux, False, None)

        for i in jsonSession:
            if i == 'client':
                nCon.loadClient(jsonSession[i])
                if simple:
                    nCon.loadClient(jsonNoSession[i])
            elif i == 'ttylog':
                nCon.loadTtylog(jsonSession[i])
                if simple:
                    nCon.loadTtylog(jsonNoSession[i])
            elif i == 'session':
                nCon.loadSession(jsonSession[i])
                if simple:
                    nCon.loadSession(jsonNoSession[i])
            elif i == 'geoip':
                nCon.loadGeoIp(jsonSession[i])
                if simple:
                    nCon.loadGeoIp(jsonNoSession[i])
            elif i == 'fingerprint':
                nCon.loadFingerprint(jsonSession[i])
                if simple:
                    nCon.loadFingerprint(jsonNoSession[i])
            elif i == 'listInputs':
                for command in jsonSession[i]:
                    nCon.loadInput(command)
                if simple:
                    for command in jsonNoSession[i]:
                        nCon.loadInput(command)
            elif i == 'listAuths':
                for auth in jsonSession[i]:
                    nCon.loadAuth(auth)
                if simple:
                    for auth in jsonNoSession[i]:
                        nCon.loadAuth(auth)
            elif i == 'listDownloads':
                for download in jsonSession[i]:
                    nCon.loadDownload(download)
                if simple:
                    for download in jsonNoSession[i]:
                        nCon.loadDownload(download)
        if simple:
            return nCon
        else:

            return nCon
