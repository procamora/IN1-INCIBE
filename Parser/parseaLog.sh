#!/bin/bash

function parser() {

	python3 run.py -d /home/procamora/Documents/LogsCowrie/github_scriptzteam/ -o /home/procamora/Documents/LogsCowrie/output_scriptzteam/ -v
	python3 run.py -d /home/procamora/Documents/LogsCowrie/raspberrypi/ -o /home/procamora/Documents/LogsCowrie/output_raspberry/ -v
	python3 run.py -d /home/procamora/Documents/LogsCowrie/docker/ -o /home/procamora/Documents/LogsCowrie/output_docker/ -v
	python3 run.py -d /home/procamora/Documents/LogsCowrie/github_kareiva/ -o /home/procamora/Documents/LogsCowrie/output_kareiva/ -v


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

	cd ..
}


#parser
elk