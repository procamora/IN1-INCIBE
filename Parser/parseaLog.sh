#!/bin/bash

function parser() {

	python3 run.py -d /home/procamora/Documents/LogsCowrie/github_scriptzteam/ -o /home/procamora/Documents/LogsCowrie/output_scriptzteam/ -v
	python3 run.py -d /home/procamora/Documents/LogsCowrie/raspberrypi/ -o /home/procamora/Documents/LogsCowrie/output_raspberry/ -v
	python3 run.py -d /home/procamora/Documents/LogsCowrie/docker/ -o /home/procamora/Documents/LogsCowrie/output_docker/ -v
	python3 run.py -d /home/procamora/Documents/LogsCowrie/github_kareiva/ -o /home/procamora/Documents/LogsCowrie/output_kareiva/ -v

#python3 run.py -d /run/media/procamora/BackUp/LOG_INCIBE/home/data/cowrie/S7/ -o /home/procamora/Documents/LogsCowrie/output_s7/ -v
#python3 run.py -d /run/media/procamora/BackUp/LOG_INCIBE/home/data/cowrie/S3/ -o /home/procamora/Documents/LogsCowrie/output_s3/ -v
#python3 run.py -d /run/media/procamora/BackUp/LOG_INCIBE/home/data/cowrie/S6/ -o /home/procamora/Documents/LogsCowrie/output_s6/ -v
}


function elk() {
	cd utils
	python3 elasticsearchLib.py -f inicial.json -i cowrie-test -m mapping_compatible.json -v

	
	python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_scriptzteam/cowrie.compatible.json -i cowrie-scriptzteam -m mapping_compatible.json -v
	python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_scriptzteam/cowrie.nosession.json.2.json -i cowrie-scriptzteam-ip -m mapping_compatible.json -v

	python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_raspberry/cowrie.compatible.json -i cowrie-raspberry -m mapping_compatible.json -v
	python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_raspberry/cowrie.nosession.json.2.json -i cowrie-raspberry-ip -m mapping_compatible.json -v

	python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_docker/cowrie.compatible.json -i cowrie-docker -m mapping_compatible.json -v
	python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_docker/cowrie.nosession.json.2.json -i cowrie-docker-ip -m mapping_compatible.json -v

	python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_kareiva/cowrie.compatible.json -i cowrie-kareiva -m mapping_compatible.json -v
	python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_kareiva/cowrie.nosession.json.2.json -i cowrie-kareiva-ip -m mapping_compatible.json -v

#python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_s3/cowrie.compatible.json -i cowrie-s3 -m mapping_compatible.json -v
#python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_s3/cowrie.nosession.json.2.json -i cowrie-s3-ip -m mapping_compatible.json -v

#python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_s6/cowrie.compatible.json -i cowrie-s6 -m mapping_compatible.json -v
#python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_s6/cowrie.nosession.json.2.json -i cowrie-s6-ip -m mapping_compatible.json -v

#python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_s7/cowrie.compatible.json -i cowrie-s7 -m mapping_compatible.json -v
#python3 elasticsearchLib.py -f /home/procamora/Documents/LogsCowrie/output_s7/cowrie.nosession.json.2.json -i cowrie-s7-ip -m mapping_compatible.json -v

	cd ..
}


#parser
elk