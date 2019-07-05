#!/bin/env python3
# -*- coding: utf-8 -*-

QUERY_SIZE = 10000

# Query para buscar todas las descargas en las que aun no se ha puesto su peligrosidad
json_search_dangerous_unused = \
    {
        "size": QUERY_SIZE,
        "query": {
            "term": {"dangerous": -1}
        }
    }

# Query para buscar todos los comandos wget y curl que se han ejecutado
json_search_wgets = \
    {
        "size": QUERY_SIZE,
        "query": {
            "bool": {
                "should": [
                    {"term": {"binary": "wget"}},
                    {"term": {"binary": "curl"}}
                ]
            }
        }
    }

# Query para buscar las descargas cuya url esta offline y no podemos acceder a ella
json_search_url_offline = \
    {
        "size": QUERY_SIZE,
        "query": {
            "bool": {
                "must": [
                    {"match": {"eventid": "cowrie.session.file_download"}},
                    {"match": {"shasum.keyword": "-1"}},
                    {"match": {"outfile.keyword": "-1"}}
                ]
            }
        }
    }
