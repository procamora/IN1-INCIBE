#!/bin/bash

IPWAN=$(ip route get 8.8.4.4 | head -1 | awk '{print $7}')
echo $IPWAN


if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

software=( cowrie-scriptzteam cowrie-scriptzteam-ip cowrie-raspberry cowrie-raspberry-ip 
	cowrie-docker cowrie-docker-ip cowrie-kareiva cowrie-kareiva-ip )

for INDEX in "${software[@]}"; do
	echo $INDEX
	rm -f $(pwd)/data/$INDEX.json

	echo $(pwd)/data
	echo http://$IPWAN:9200/$INDEX
	echo /tmp/$INDEX.json
	echo 

	docker run --rm -ti -v $(pwd)/data:/tmp taskrabbit/elasticsearch-dump \
		--input=http://$IPWAN:9200/$INDEX \
		--output=/tmp/$INDEX.json
done


