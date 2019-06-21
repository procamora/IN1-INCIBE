#!/bin/env python3
# -*- coding: utf-8 -*-

import configparser
import glob
import re
import traceback
from timeit import default_timer as timer

import geoip2.database

from connectionAux import ConnectionAux
from download import Download
from newConnection import NewConnection
from utils.functions import parserIp, getSession, parserDateTime, parserIdtoSession, parserIdIp, writeFile, \
    parserIpAnyLine, checkDir


class Parser(object):
    """
    Clase Parser encargada de parsear los ficheros de log
    """

    def __init__(self, logger, output, workingDir, myConfig):
        """
        Constructor de clase

        :param logger: Instancia de logging
        :param output: Directorio donde se guardan los ficheros de salida
        :param workingDir: Directorio donde se encuentran los log a analizar
        """
        config = configparser.ConfigParser()
        config.sections()
        config.read('settings.conf')

        checkDir(output)

        self._logger = logger
        self._logCompleted = '{}/{}'.format(output, config[myConfig]['FILE_LOG_COMPLETED'])
        self._logAuxSession = '{}/{}'.format(output, config[myConfig]['FILE_LOG_SESSION'])
        self._logAuxNoSession = '{}/{}'.format(output, config[myConfig]['FILE_LOG_NOSESSION'])
        self._geoip2DB = None
        self._workingDir = workingDir

        self._connectionWget = list()  # conexiones que han ejecutado un wget y hay que enlazarlo con la respuesta
        self._listCommandWget = list()  # Comandos wget ejecutados

        # Creamos el fichero con los insert y si existe lo vacia
        with open(self._logCompleted, 'w'):
            pass
        # Creamos el fichero con los insert y si existe lo vacia
        with open(self._logAuxSession, 'w'):
            pass
        # Creamos el fichero con los insert y si existe lo vacia
        with open(self._logAuxNoSession, 'w'):
            pass

    def parse(self, db):
        """
        Metodo para arancar el proceso de parsear ficheros

        :return:
        """

        self._geoip2DB = geoip2.database.Reader(db)
        startTotal = timer()
        for fname in sorted(glob.glob('{}/cowrie.log.*'.format(self._workingDir))):
            # for fname in sorted(glob.glob('{}/analizame.log'.format(self._workingDir))):
            self._logger.info('Analizando: {}'.format(fname))

            self._connectionWget.clear()  # Vaciamos la lista/diccionario porque no tiene informacion util en otro log
            self._listCommandWget.clear()

            start = timer()
            try:
                connectionAuxDict = Parser.getConnections(fname)
                newConnectionDict = self.setIPtoID(connectionAuxDict, fname)
                self.getInfoLog(newConnectionDict, fname)
            except UnicodeDecodeError as error:
                self._logger.error('Unicode decode error in file: {}'.format(fname))
                self._logger.debug(traceback.print_tb(error.__traceback__))
            end = timer()
            #self._logger.debug('Time file: {}'.format(end - start))  # Time in seconds

        endTotal = timer()
        self._logger.info('Time total: {} seg'.format(endTotal - startTotal))  # Time in seconds, e.g. 5.38091952400282
        self._geoip2DB.close()

    @staticmethod
    def getConnections(fname):
        """
        Metodo inicial que busca todas las New Connection que hay en el fichero y las asocia a la linea en la que estan

        :param fname:
        :return: Map<int, ConnectionAux>
        """
        connectionAuxDict = dict()  # asociacion de linea de la primera conexion con id session
        with open(fname, 'r') as fp:
            for numLine, line in enumerate(fp):
                # evitamos errores por lineas en blanco
                if re.match(r'.*New connection:.*', line, re.IGNORECASE) and \
                        re.match(r'.*session: (\w+).*', line, re.IGNORECASE):
                    connectionAux = ConnectionAux(parserIp(line), getSession(line), parserDateTime(line))
                    connectionAuxDict[numLine + 1] = connectionAux  # Linea en la que estara la _ip con el id

        return connectionAuxDict

    def setIPtoID(self, connectionAuxDict, fname):
        """
        Asociamos una IP a su ID que lo identificara en cada una de las lineas del log [HoneyPotSSHTransport,id,ip]
        Devolvemos una lista de conexiones con la informacion que necesitamos para obtener el resto de datos

        :param connectionAuxDict:
        :param fname:
        :return: Map<String ,newConnectionDict>
        """

        newConnectionDict = dict()

        # Leemos el fichero y lo guardamos en un array por lineas
        with open(fname, 'r') as fp:
            file = fp.readlines()

        fileSize = len(file)  # Comprobar que no superamos el array

        # Para cada conexion que tenemos buscamos cual es la primera linea que tiene su ip con el id
        for connection in connectionAuxDict:
            valid = True  # Condicion que se modifica si no se lleva al final del fichero sin encontrar una asociacion
            cont = connection
            s = str()
            if cont < fileSize:  # si la linea esta en la ultima linea no buscamos mas
                s = file[cont]
            else:
                valid = False

            # Avanzamos las lineas necesarias hasta tener una linea con la ip de la conexion
            while valid and not re.match(r'.*,\d+,{}'.format(connectionAuxDict[connection].getIp()), s, re.IGNORECASE):
                cont += 1
                if cont < fileSize:
                    s = file[cont]
                else:
                    self._logger.info(
                        'No puedo con: {} en linea: {}'.format(connectionAuxDict[connection].getIp(), connection))
                    valid = False

            if valid:
                connectionAuxDict[connection].setId(parserIdtoSession(s))  # Establecemos el id de la conexion
                if connectionAuxDict[connection].getId() in newConnectionDict:
                    pass  # Posteriores conexiones con la misma id,ip los omitimos porque iran al objeto ya creado
                else:
                    newConnectionDict[connectionAuxDict[connection].getId()] = NewConnection(
                        connectionAuxDict[connection], self._logger, self._geoip2DB)

        return newConnectionDict

    def getInfoLog(self, newConnectionDict, fname):
        """
        Metodo que recorre el fichero linea a linea y si existe el indice id,ip en el diccionario obtiene ek objeto
        asociado a ese indice y le añade esa linea, que solo guardara si tiene informacion util

        :param newConnectionDict:
        :param fname:
        :return:
        """

        with open(fname, 'r') as fp:
            for line in fp:
                info = parserIdIp(line)
                if info is not None:
                    if info in newConnectionDict:  # Las lineas que tenemos en el diccionario las parseamos
                        newConnectionDict[info].addLine(line)
                        if re.match(r'.*CMD:.*wget.*', line, re.IGNORECASE):
                            self._connectionWget.append(info)  # si la linea contiene un wget guardo esa conexion
                    else:  # Lineas con id,ip pero que no tienen New connection y no estan en el diccionario
                        conAux = ConnectionAux(parserIpAnyLine(line), '', '')
                        conAux.setId(parserIdtoSession(line))
                        newConnectionDict[info] = NewConnection(conAux, self._logger, self._geoip2DB)
                        newConnectionDict[info].addLine(line)
                else:  # Lineas que no tienen id,ip
                    # Añadimos al fichero auxiliar de lineas no tratadas todas las lineas que no tengan la id,ip en el
                    # el diccionario y que no sean una New connection ya que estan ya han sido tratadas
                    if not re.match(r'.*New connection:.*', line, re.IGNORECASE) and len(line) > 2:
                        regex = r'^.*Downloaded URL \(b?\'(.*)\'\) with SHA-\d+ (\w+) to (.*)$'
                        if re.match(regex, line, re.IGNORECASE):
                            d = re.search(regex, line, re.IGNORECASE)
                            download = Download(d.group(1), d.group(2), d.group(3), parserDateTime(line))
                            self._listCommandWget.append(download)

        self.updateCommandConnection(newConnectionDict)

        for conect in newConnectionDict.values():
            if conect.isCompleted():
                writeFile(conect.getJSON(), self._logCompleted, 'a')
            elif conect.isSession():
                writeFile(conect.getJSON(), self._logAuxSession, 'a')
            else:
                writeFile(conect.getJSON(), self._logAuxNoSession, 'a')

    def searchWget(self, newConnectionDict, command):
        """
        Metodo que recorre la lista de conexiones que han ejecutado un comand wget, si el comando corresponde con
        el que estamos tratando le actualiza los valores y lo borra de la lista

        :param newConnectionDict:
        :param command:
        :return:
        """
        for connection in self._connectionWget:
            if newConnectionDict[connection].checkCommandPending(command):
                self._connectionWget.remove(connection)
                return

    def updateCommandConnection(self, newConnectionDict):
        """
        Metodo que recorre todos los comandos  wget ejecutados para comprobar si en el diccionario de conexiones se ha
        ejecutado

        :param newConnectionDict:
        :return:
        """
        # Aqui tenemos que recorrer cada comando y comprobar si tiene una wget pendiente de obtener un valor
        for command in self._listCommandWget:
            # self._logger.info(command.toString())
            self.searchWget(newConnectionDict, command)
