#!/bin/bash
# Parse PCAP to CSV
PARSER_PATH=$1
PCAP_DIR=$2

if [ -z $PCAP_DIR ] && [ -z $PARSER_PATH ]; then
  echo "usage: bash $0 <path to pcap parser> <pcap directory>";
  exit
fi

for FILE in $(find $PCAP_DIR -name "*cap" -type f); do
  FILENAME=$(basename $FILE)
  DIRNAME=$(dirname $FILE)

  python3 $PARSER_PATH/parser.py $FILE
done
