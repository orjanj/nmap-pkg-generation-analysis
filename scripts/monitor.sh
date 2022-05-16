#!/bin/bash
YEAR=$(date +%Y) # one issue - when running the research on 31.12 -> 01.01, this process monitor would not give correct result (bug)
while true
do
    clear
    echo "Worker_Host Process_Name Task" > ps_tmp
    ps -eo command | grep -E '^ssh.*tcpdump' | grep -v grep | sed 's/-U -i ens33 -w //g' | sed "s/_$YEAR.*$//g" | sed 's/ssh //g' >> ps_tmp
    ps -eo command | grep -E "^nmap" | sed 's/.\/results\///g' | sed "s/_$YEAR.*.xml//g" | awk '{ print $4 " " $1 " " $3 }' >> ps_tmp
    column ps_tmp -t -s " " | grep 'Worker_Host'
    column ps_tmp -t -s " " | grep -v 'Worker_Host' | sort
    sleep 2
done

# TODO: ens33 must be changed with dynamic fetched NIC name