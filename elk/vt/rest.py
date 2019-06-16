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
import time
import json
import os

from connect_sqlite import isNewMD5, isNewURL, selectMD5, selectURL, DB, ejecutaScriptSqlite, conectionSQLite, isExistsMD5
from virustotal import analizeHash, analizeUrl

requests.packages.urllib3.disable_warnings()

MIME_TYPE = 'application/json'

STATES = {
    1: "Scan finished, information embedded",                                       # "Ok",
    2: "The requested resource is not among the finished, queued or pending scans", # "Not Exists",
    3: "Scan request successfully queued, come back later for the report"           # "Analyzing"
    }

HASH_INPROGRESS = list()

app = Flask(__name__)


def myDaemon():
    while True:
        for i in HASH_INPROGRESS:
            app.logger.info("Demonio analiza: {}".format(i))
            thread_analizeHash(i)

        time.sleep(5)


def insertUpdateMD5(file, md5, json, state, url=""):
    #app.logger.info("md5: {}".format(md5))
    #app.logger.info("isNewMD5(md5): {}".format(isNewMD5(md5)))
    #app.logger.info("isNewURL(url): {}".format(isNewURL(url)))

    if isExistsMD5(md5):
        query = "INSERT INTO hash(file, md5, json, url, state) VALUES ('{}', '{}', '{}', '{}', {})".format(file, md5, json, url, state)
        #print('INSERT')
    else:
        query = "UPDATE hash SET json = '{}' WHERE md5 = '{}'".format(json, md5)
        #print('UPDATE')

    conectionSQLite(DB, query)


def getStateJson(response):
    response = json.loads(response)
    #app.logger.info("response: {}".format(response))
    app.logger.info("Code: {}".format(response['results']['response_code']))

    if response['results']['verbose_msg'] == STATES[3]:
        return 3
    elif response['results']['verbose_msg'] == STATES[2]:
        return 2
    elif response['results']['verbose_msg'] == STATES[1]:
        return 1
    else:
        return 4


def thread_analizeHash(md5, file="", url=""):
    response = analizeHash(md5)
    resp = json.loads(response)
    if resp['response_code'] == 204:
        app.logger.info("Excedidas peticiones por minuto, reintendanto: {}".format(md5))
        app.logger.info(HASH_INPROGRESS)
        #time.sleep(5)
    else:
        app.logger.info("Insertamos {} en la BD".format(md5))
        state = getStateJson(response)
        ###########################################
        ###########################################
        #Si no existe ese hash lo insertamos en caso contrario actualizamos su informacion
        insertUpdateMD5(file, md5, response, state, url)
        ###########################################
        ###########################################
        ###########################################
        HASH_INPROGRESS.remove(md5)
    return response


def thread_analizeUrl(url, file):
    # es un bucle hasta que tengamos respuesta
    response = analizeUrl(url)
    state = getStateJson(response)
    ###########################################
    ###########################################
    #Si no existe ese hash lo insertamos en caso contrario actualizamos su informacion
    insertUpdateMD5(file, "md5", response, state, url)
    ###########################################
    ###########################################
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
        if (not newHash in HASH_INPROGRESS) and (isNewMD5(newHash)):
            app.logger.info("Insertamos %s en la BD", file_name)
            HASH_INPROGRESS.append(newHash)
            thread_analizeHash(newHash, file_name, file_url) # Aqui no es un hilo

        #######os.remove(file_name) # FIXME DESCOMENTAR
    app.logger.info("Thread %s: finishing", file_name)


@app.route('/', methods=['GET', 'POST'])
def hello():
    return Response(response='{"status": "ok"}', status=HTTPStatus.OK, mimetype=MIME_TYPE)


@app.route('/analize', methods=['GET'])
def virustotalMD5():
    md5 = requestFlask.args.get('md5')

    if (not md5 in HASH_INPROGRESS) and (isNewMD5(md5)):
        HASH_INPROGRESS.append(md5)
        response = thread_analizeHash(md5)
        return Response(response=response, status=HTTPStatus.PARTIAL_CONTENT, mimetype=MIME_TYPE)
    else:
        response = selectMD5(md5)
        return Response(response=response['json'], status=HTTPStatus.OK, mimetype=MIME_TYPE)


@app.route('/analize', methods=['POST'])
def virustotalURL():
    values = requestFlask.get_json()
    file_url = str(values['url'])
    file_name = file_url.split('/')[-1]

    if not isNewURL(file_url):
        response = selectURL(file_url)
        return Response(response=response['json'], status=HTTPStatus.OK, mimetype=MIME_TYPE)
    else:
        thread_analizeUrl(file_url, file_name)
        return Response(response="", status=HTTPStatus.PARTIAL_CONTENT, mimetype=MIME_TYPE)


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
        return Response(response=file_name, status=HTTPStatus.PARTIAL_CONTENT, mimetype=MIME_TYPE)
    else:
        return Response(response='{"error": "File not downloadable"}', status=HTTPStatus.FORBIDDEN, mimetype=MIME_TYPE)



if __name__ == "__main__":
    if not os.path.isfile(DB):
        print("Creamos BD: {}".format(DB))
        with open('hash.sql', 'r') as f:
            ejecutaScriptSqlite(DB, f.read())

    d = threading.Thread(target=myDaemon, name='Daemon', daemon=True)
    d.start()
    app.run(debug=True, port=8080)

