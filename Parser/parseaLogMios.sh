#!/bin/bash


function elk() {
	cd utils
	
	python3 elasticsearchLib.py -f /home/procamora/TFG/UM-TFG/log/github_scriptzteam/cowrie.completed.json -i cowrie-scriptzteam -m mapping.json -v
	python3 elasticsearchLib.py -f /home/procamora/TFG/UM-TFG/log/github_scriptzteam/cowrie.nosession.json.2.json -i cowrie-scriptzteam-ip -m mappingIP.json -v

	python3 elasticsearchLib.py -f /home/procamora/TFG/UM-TFG/log/docker/cowrie.completed.json -i cowrie-docker -m mapping.json -v
	python3 elasticsearchLib.py -f /home/procamora/TFG/UM-TFG/log/docker/cowrie.nosession.json.2.json -i cowrie-docker-ip -m mappingIP.json -v

	python3 elasticsearchLib.py -f /home/procamora/TFG/UM-TFG/log/github_kareiva/cowrie.completed.json -i cowrie-kareiva -m mapping.json -v
	python3 elasticsearchLib.py -f /home/procamora/TFG/UM-TFG/log/github_kareiva/cowrie.nosession.json.2.json -i cowrie-kareiva-ip -m mappingIP.json -v

	python3 elasticsearchLib.py -f /home/procamora/TFG/UM-TFG/log/raspberrypi/cowrie.completed.json -i cowrie-raspberrypi -m mapping.json -v
	python3 elasticsearchLib.py -f /home/procamora/TFG/UM-TFG/log/raspberrypi/cowrie.nosession.json.2.json -i cowrie-raspberrypi-ip -m mappingIP.json -v

	cd ..
}


#parser
elk