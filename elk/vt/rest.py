#!/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, Response
from flask import request as requestFlask
from filehash import FileHash
from http import HTTPStatus # https://docs.python.org/3/library/http.html
import threading
import requests
import logging
import hashlib
import json
import os

from connect_sqlite import conectionSQLite
from virustotal import analize

requests.packages.urllib3.disable_warnings()

MIME_TYPE = 'application/json'
DB = "virustotal.db"

HASH_INPROGRESS = list()

app = Flask(__name__)


def isNewMD5(md5):
    query = "SELECT * FROM hash WHERE md5 LIKE '{}'".format(md5)
    response = conectionSQLite(DB, query, True)
    if len(response) == 0:
        return True
    return False


def isNewURL(url):
    query = "SELECT * FROM hash WHERE url LIKE '{}'".format(url)
    response = conectionSQLite(DB, query, True)
    if len(response) == 0:
        return True
    return False


def insertMD5(file, md5, json, url=""):
    query = "INSERT INTO hash(file, md5, json, url) VALUES ('{}', '{}', '{}', '{}')".format(file, md5, json, url)
    conectionSQLite(DB, query)


def selectMD5(md5):
    query = "SELECT * FROM hash WHERE md5 LIKE '{}'".format(md5)
    return conectionSQLite(DB, query, True)[0]


def selectURL(url):
    query = "SELECT * FROM hash WHERE url LIKE '{}'".format(url)
    return conectionSQLite(DB, query, True)[0]


def thread_analizeHash(md5, file="", url=""):
    # es un bucle hasta que tengamos respuesta
    HASH_INPROGRESS.append(md5)
    response = analize(md5)
    insertMD5(file, md5, response, url)
    HASH_INPROGRESS.remove(md5)
    return response


def is_downloadable(url):
    """
    Does the url contain a downloadable resource
    """
    h = requests.head(url, allow_redirects=True, verify=False)
    header = h.headers
    content_type = header.get('content-type')
    app.logger.error(content_type)
    #if 'text' in content_type.lower():
    #    return False
    if 'html' in content_type.lower():
        return False
    return True


def thread_downloadFile(file_url, file_name):
    app.logger.info("Thread %s: starting", file_name)
    r = requests.get(file_url, verify=False)
    if r.status_code == HTTPStatus.OK:
        # Copiamos los ficheros por bloques
        with open(file_name, 'wb') as pdf: 
            for chunk in r.iter_content(chunk_size=1024): 
                if chunk: 
                    pdf.write(chunk) 

        md5hasher = FileHash('md5')
        newHash = md5hasher.hash_file("./{}".format(file_name))
        if isNewMD5(newHash):
            app.logger.info("Insertamos %s en la BD", file_name)
            thread_analizeHash(newHash, file_name, file_url) # Aqui no es un hilo
            #insertMD5(file_name, newHash, '{"a":"b"}')

        #######os.remove(file_name)
    app.logger.info("Thread %s: finishing", file_name)


@app.route('/', methods=['GET', 'POST'])
def hello():
    return Response(response='{"status": "ok"}', status=HTTPStatus.OK, mimetype=MIME_TYPE)


@app.route('/vt', methods=['GET'])
def virustotal():
    md5 = requestFlask.args.get('md5')

    if (not md5 in HASH_INPROGRESS) and (isNewMD5(md5)):
        x = threading.Thread(target=thread_analizeHash, args=(md5))
        x.start()
        return Response(response="", status=HTTPStatus.CREATED, mimetype=MIME_TYPE)
    else:
        response = selectMD5(md5)
        return Response(response=response['json'], status=HTTPStatus.OK, mimetype=MIME_TYPE)


@app.route('/download', methods=['POST'])
def download():
    values = requestFlask.get_json()
    file_url = str(values['url'])
    file_name = file_url.split('/')[-1]

    if not isNewURL(file_url):
        response = selectURL(file_url)
        return Response(response=response['json'], status=HTTPStatus.OK, mimetype=MIME_TYPE)

    if is_downloadable(file_url):
        x = threading.Thread(target=thread_downloadFile, args=(file_url, file_name))
        x.start()
        return Response(response=file_name, status=HTTPStatus.CREATED, mimetype=MIME_TYPE)
    else:
        return Response(response='{"error": "File not downloadable"}', status=HTTPStatus.FORBIDDEN, mimetype=MIME_TYPE)


if __name__ == "__main__":
    if not os.path.isfile(DB):
        app.logger.info("Creamos BD: ", DB)
        os.system('sqlite3 {} < hash.sql'.format(DB))

    app.run(debug=True, port=8080)

