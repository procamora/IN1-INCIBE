
# Elasticsearch

$ grep vm.max_map_count /etc/sysctl.conf
vm.max_map_count=262144

vm.max_map_count=262144 



IPWAN=$(ip route get 8.8.4.4 | head -1 | awk '{print $7}')
echo $IPWAN

INDEX=cowrie-scriptzteam
docker run --rm -ti -v /data:/tmp taskrabbit/elasticsearch-dump \
  --input=http://$IPWAN:9200/$INDEX \
  --output=$INDEX.json \
  --type=data