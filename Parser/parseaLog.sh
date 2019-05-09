#!/bin/bash

function parser() {

	python3 run.py -d /run/media/procamora/BackUp/LOG_INCIBE/S3/ -o /run/media/procamora/BackUp/LOG_INCIBE/S3_JSON/ -v
	python3 run.py -o /run/media/procamora/BackUp/LOG_INCIBE/S3_JSON/ -v


	python3 run.py -d /run/media/procamora/BackUp/LOG_INCIBE/S6/ -o /run/media/procamora/BackUp/LOG_INCIBE/S6_JSON/ -v
	python3 run.py -o /run/media/procamora/BackUp/LOG_INCIBE/S6_JSON/ -v

	python3 run.py -d /run/media/procamora/BackUp/LOG_INCIBE/S7/ -o /run/media/procamora/BackUp/LOG_INCIBE/S7_JSON/ -v
	python3 run.py -o /run/media/procamora/BackUp/LOG_INCIBE/S7_JSON/ -v

}


function elk() {
	cd utils
	
	python3 elasticsearchLib.py -f /run/media/procamora/BackUp/LOG_INCIBE/S3_JSON/cowrie.completed.json -i cowrie-s3 -m mapping.json -v
	python3 elasticsearchLib.py -f /run/media/procamora/BackUp/LOG_INCIBE/S3_JSON/cowrie.nosession.json.2.json -i cowrie-s3-ip -m mappingIP.json -v

	python3 elasticsearchLib.py -f /run/media/procamora/BackUp/LOG_INCIBE/S6_JSON/cowrie.completed.json -i cowrie-s6 -m mapping.json -v
	python3 elasticsearchLib.py -f /run/media/procamora/BackUp/LOG_INCIBE/S6_JSON/cowrie.nosession.json.2.json -i cowrie-s6-ip -m mappingIP.json -v

	python3 elasticsearchLib.py -f /run/media/procamora/BackUp/LOG_INCIBE/S7_JSON/cowrie.completed.json -i cowrie-s7 -m mapping.json -v
	python3 elasticsearchLib.py -f /run/media/procamora/BackUp/LOG_INCIBE/S7_JSON/cowrie.nosession.json.2.json -i cowrie-s7-ip -m mappingIP.json -v

	cd ..
}


#parser
elk