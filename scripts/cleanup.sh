#!/bin/bash
TASK_FILE=$1
RESULT_DIR="./results"

if [[ -z $TASK_FILE ]]; then
    echo "Usage: $0 <task_file>"
    exit
fi

process_comparision_clean() {
    YEAR=$(date +%Y)
    ps -eo command | grep tcpdump | grep -v grep | sed 's/^ssh.*-w //g' | sed "s/_$YEAR.*$//g" > ps_comparision

    while read TASK_NAME
    do
        SCANNER_PID=$(ps -eo pid,command | grep "$TASK_NAME" | grep -Ev 'tcpdump|grep' | awk '{ print $1 }')
        if [[ -z $SCANNER_PID ]]; then
            terminate_tcpdump $TASK_NAME
        fi

    done < ps_comparision
}

# -----------------------------------
# Color messages
# -----------------------------------
colored_message() {
    COLOR=$1
    MESSAGE="$2"
    if [[ $COLOR == "red" ]]; then
        echo -e "[ \e[31m\e[1mError\e[0m ] $MESSAGE\n"
    elif [[ $COLOR == "green" ]]; then
        echo -e "[ \e[32m\e[1mSuccess\e[0m ] $MESSAGE\n"
    else
        echo -e "$MESSAGE\n"
    fi
}

check_scan_status() {
    TASK_NAME=$1
    SCANNER_PROCESS_INFO=$(ps aux | grep "${RESULT_DIR}/${TASK_NAME}_" | grep -v grep)
    SCANNER_LOCAL_PID=$(echo $SCANNER_PROCESS_INFO | awk '{ print $2 }')

    if [[ ! -z $SCANNER_LOCAL_PID ]]; then
        return 1 # return false - still working
    else
        return 0 # return true - work done
    fi
}


# -----------------------------------
# Terminate tcpdump on worker
# -----------------------------------
terminate_tcpdump() {
    TASK_NAME=$1

    PROCESS_INFO=$(ps aux | grep -E "(tcpdump).*($TASK_NAME)_" | grep -v grep)
    if [[ ! -z $PROCESS_INFO ]]; then

        LOCAL_PID=$(echo $PROCESS_INFO | awk '{ print $2 }')
        WORKER_HOST=$(echo $PROCESS_INFO | awk -F 'ssh' '{ print $2 }' | awk '{ print $1 }')
# a probable bug:
#        WORKER_HOST=$(echo $PROCESS_INFO | awk '{ print $12 }')
        REMOTE_PIDS=$(ssh $WORKER_HOST ps aux | grep -E "(tcpdump).*($TASK_NAME)" | awk '{ print $2 }')
        REMOTE_PIDS_VIEW=$(echo $REMOTE_PIDS | tr "\n" " ")

#        ssh $WORKER_HOST pkill tcpdump
#        kill -15 $LOCAL_PID
        ssh $WORKER_HOST kill -15 $REMOTE_PIDS_VIEW
        STATUS=$?
        return $STATUS
    fi
}


# -----------------------------------
# Change status on a task
# -----------------------------------
task_change() {
    TASK_NAME=$1
    PRIORITY=$2
    OLD_STATUS=$3
    NEW_STATUS=$4

    OLD_CSV_ENTRY="$PRIORITY,$TASK_NAME,$OLD_STATUS"
    NEW_CSV_ENTRY="$PRIORITY,$TASK_NAME,$NEW_STATUS"

    if sed -i -e "s/$OLD_CSV_ENTRY/$NEW_CSV_ENTRY/g" $TASK_FILE; then
        return 0 # true (success)
    else
        return 1 # false (error)
    fi
}


update_tasklist() {
#    process_comparision_clean
    # Read through the tasks in the task file
    while IFS=, read -r PRIORITY TASK_NAME TASK_STATUS SCANNER EXTRA_ARGS
    do
        # Make sure that the task is not the header in the task file
        if [[ $TASK_STATUS == "ongoing" ]]; then
            check_scan_status $TASK_NAME
            SCAN_STATUS=$?

            if [[ $SCAN_STATUS -eq 0 ]]; then
                if terminate_tcpdump $TASK_NAME; then
                    task_change $TASK_NAME $PRIORITY "ongoing" "completed"
                else
                    colored_message "red" "Unable to terminate traffic capture on task \e[1m${TASK_NAME}\e[0m."
                fi
            fi
        fi
    done < $TASK_FILE
}


while true
do
    if update_tasklist; then
        DATE=$(date "+%d.%m.%Y %H:%M:%S")
        printf "\r[ $DATE ] Cleaned taskfile: $TASK_FILE"
        sleep 2
    else
        printf "\r[ $DATE ] Failed cleaning taskfile: $TASK_FILE"
    fi
done