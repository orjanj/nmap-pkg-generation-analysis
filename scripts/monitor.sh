#!/bin/bash
YEAR=$(date +%Y)
while true
do
    clear
    echo "Worker_Host Process_Name Task" > ps_tmp
    ps -eo command | grep -E '^ssh.*tcpdump' | grep -v grep | sed 's/-U -i ens33 -w //g' | sed "s/_$YEAR.*$//g" | sed 's/ssh //g' >> ps_tmp
    ps -eo command | grep -E "^nmap" | sed 's/.\/results\///g' | sed 's/_2022.*.xml//g' | awk '{ print $4 " " $1 " " $3 }' >> ps_tmp
    column ps_tmp -t -s " " | sort
    sleep 2
done