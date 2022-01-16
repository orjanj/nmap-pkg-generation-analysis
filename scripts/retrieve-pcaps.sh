#!/bin/bash
# This script will sync pcap files from workers based on filters
WORKER_HOSTS=(bsc01-mng bsc02-mng bsc03-mng bsc04-mng bsc05-mng bsc06-mng bsc07-mng bsc08-mng bsc09-mng bsc10-mng bsc11-mng bsc12-mng bsc13-mng bsc14-mng bsc15-mng bsc16-mng bsc17-mng bsc18-mng bsc19-mng bsc20-mng)
PCAP_FILTER_NAME=$1
OUTPUT_DIRECTORY=$2

if [[ -z $PCAP_FILTER_NAME ]] || [[ -z $OUTPUT_DIRECTORY ]]; then
    echo "Usage: $0 <pcap file filter name> <sync destination>"
    exit
fi

for WORKER_HOST in ${WORKER_HOSTS[@]};
do
    rsync -azvv -e ssh "bscadm@$WORKER_HOST:$PCAP_FILTER_NAME*.pcap" $OUTPUT_DIRECTORY/
done