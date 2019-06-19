#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sqlite3

DB = "virustotal.db"


def conectionSQLite(db, query, isDict=False):
    if os.path.exists(db):
        conn = sqlite3.connect(db)
        if isDict:
            conn.row_factory = dictFactory
        cursor = conn.cursor()
        cursor.execute(query)

        if query.upper().startswith('SELECT'):
            data = cursor.fetchall()  # Traer los resultados de un select
        else:
            conn.commit()  # Hacer efectiva la escritura de datos
            data = None

        cursor.close()
        conn.close()

        return data


def dictFactory(cursor, row):
    d = dict()
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def ejecutaScriptSqlite(db, script):
    conn = sqlite3.connect(db)
    cursor = conn.cursor()
    cursor.executescript(script)
    conn.commit()
    cursor.close()
    conn.close()


def dumpDatabase(db):
    """
    Hace un dump de la base de datos y lo retorna
    :param db: ruta de la base de datos
    :return dump: volcado de la base de datos 
    """
    if os.path.exists(db):
        con = sqlite3.connect(db)
        # noinspection PyTypeChecker
        return '\n'.join(con.iterdump())


# un hash existe si esta en la bd con state 1 (Ok)
def isExistsMD5(md5):
    query = "SELECT * FROM hash WHERE md5 LIKE '{}'".format(md5)
    response = conectionSQLite(DB, query, True)
    if len(response) == 0:
        return True
    return False


# un hash existe si esta en la bd con state 1 (Ok)
def isNewMD5(md5):
    query = "SELECT * FROM hash WHERE md5 LIKE '{}' AND state LIKE 1".format(md5)
    response = conectionSQLite(DB, query, True)
    if len(response) == 0:
        return True
    return False


# un hash existe si esta en la bd con state 1 (Ok)
def isNewURL(url):
    query = "SELECT * FROM hash WHERE url LIKE '{}' AND state LIKE 1".format(url)
    response = conectionSQLite(DB, query, True)
    if len(response) == 0:
        return True
    return False


def selectMD5(md5):
    query = "SELECT * FROM hash WHERE md5 LIKE '{}'".format(md5)
    response = conectionSQLite(DB, query, True)
    if len(response) > 0:
        return response[0]
    return None


def selectURL(url):
    query = "SELECT * FROM hash WHERE url LIKE '{}'".format(url)
    response = conectionSQLite(DB, query, True)
    if len(response) > 0:
        return response[0]
    return None
