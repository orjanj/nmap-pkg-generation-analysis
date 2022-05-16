#!/bin/bash
INPUT_FILE=$1

if [[ -z $INPUT_FILE ]]; then
    echo "Usage: $0 <task-file>"
    echo "Default number of task param is \"50\" - must be changed in for loop in line 12"
    exit
fi

while IFS=, read -r PRIORITY TASK_NAME TASK_STATUS SCANNER EXTRA_ARGS
do
    for i in {1..50}
    do
        echo "${PRIORITY},${TASK_NAME}_${i},${TASK_STATUS},${SCANNER},${EXTRA_ARGS}"
#        echo "${TASK_NAME}_${i}"

#        TASK_NUMBER=$(echo $TASK_NAME | awk -F '_' '{ print $2 }')
#        echo $TASK_NUMBER
    done
#    NEW_TASK=$(echo $TASK_NAME | sed )
done < $INPUT_FILE