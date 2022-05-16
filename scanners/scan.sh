#!/bin/bash
# CONSTANTS
TARGET_HOSTS=(bsc01 bsc02 bsc03 bsc04 bsc05 bsc06 bsc07 bsc08 bsc09 bsc10 bsc11 bsc12 bsc13 bsc14 bsc15 bsc16 bsc17 bsc18 bsc19 bsc20)
WORKER_HOSTS=(bsc01-mng bsc02-mng bsc03-mng bsc04-mng bsc05-mng bsc06-mng bsc07-mng bsc08-mng bsc09-mng bsc10-mng bsc11-mng bsc12-mng bsc13-mng bsc14-mng bsc15-mng bsc16-mng bsc17-mng bsc18-mng bsc19-mng bsc20-mng)
RESULT_DIR="./results"
TASK_FILE="tasklist.csv"
DEFAULT_IF="ens33"
TCPDUMP_FILTER="ip and dst not 192.168.2.1 and src not 192.168.2.1"

# Currently unused variables
SUBNET="192.168.2.0/24"
ZOMBIE_HOST=192.168.2.252


# -----------------------------------
# Tasking
# -----------------------------------
CUSTOM_TASK_FILE=$1
if [[ -z $CUSTOM_TASK_FILE ]]; then
    TASK_FILE="tasklist.csv"
    echo "Using default task file.."
else
    TASK_FILE="$CUSTOM_TASK_FILE"
    echo "Starting scanner with custom task file: $TASK_FILE"
fi


# -----------------------------------
# Get task information
# -----------------------------------
get_task_name() {
    WORKER_HOST=$1
    TARGET_HOST=$(echo $WORKER_HOST | sed 's/-mng//g')
    TCPDUMP_PROCESS_INFO=$(ps aux | grep $WORKER_HOST | grep tcpdump)
    TASK_NAME=$(echo $TCPDUMP_PROCESS_INFO | awk -F '-w ' '{ print $2 }' | sed 's/.pcap 2>&1//g')
    echo $TASK_NAME
}


# -----------------------------------
# Color messages
# -----------------------------------
colored_message() {
    COLOR=$1
    MESSAGE="$2"
    if [[ $COLOR == "red" ]]; then
        echo -e "[ \e[31m\e[1mError\e[0m ] $MESSAGE"
    elif [[ $COLOR == "green" ]]; then
        echo -e "[ \e[32m\e[1mSuccess\e[0m ] $MESSAGE"
    else
        echo -e "$MESSAGE"
    fi
}

# -----------------------------------
# Check scan status
# -----------------------------------
check_scan_status() {
    TASK_NAME=$1
    SCANNER_PROCESS_INFO=$(ps aux | grep "${RESULT_DIR}/${TASK_NAME}" | grep -v grep)
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

    PROCESS_INFO=$(ps aux | grep -E "(tcpdump).*($TASK_NAME)" | grep -v grep)
    if [[ ! -z $PROCESS_INFO ]]; then

        LOCAL_PID=$(echo $PROCESS_INFO | awk '{ print $2 }')
        WORKER_HOST=$(echo $PROCESS_INFO | awk -F 'ssh' '{ print $2 }' | awk '{ print $1 }')
# a probable bug:
#        WORKER_HOST=$(echo $PROCESS_INFO | awk '{ print $12 }')
        REMOTE_PIDS=$(ssh $WORKER_HOST ps aux | grep -E "(tcpdump).*($TASK_NAME)" | awk '{ print $2 }')
        REMOTE_PIDS_VIEW=$(echo $REMOTE_PIDS | tr "\n" " ")

        kill -15 $LOCAL_PID ; ssh $WORKER_HOST kill -15 $REMOTE_PIDS_VIEW
        STATUS=$?
        return $STATUS
    fi
}


# -----------------------------------
# Check availability for a given worker
# -----------------------------------
#   Status codes:
#   2 - unreachable
#   1 - busy
#   0 - available
# -----------------------------------
available_worker() {
    HOSTNAME=$1
    PID_TCPDUMP=$(ssh -q $HOSTNAME pgrep tcpdump)
    if ! ssh -q -T $HOSTNAME exit &> /dev/null; then
        return 2 # unreachable
    elif [[ ! -z $PID_TCPDUMP ]]; then
        return 1 # busy
    else
        return 0 # available
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


# -----------------------------------
# Find target subnet NIC for each worker
# -----------------------------------
find_listening_scanner_if() {
    WORKER_HOST=$1
    IF=$(ssh $WORKER_HOST ip r | grep $SUBNET | awk '{print $3}')
    echo $IF
}


# -----------------------------------
# Start tcpdump on a worker
# -----------------------------------
start_tcpdump() {
    WORKER_HOST=$1
    PCAP_FILENAME=$2
    INTERFACE=$(find_listening_scanner_if $WORKER_HOST)

    if ssh $WORKER_HOST "tcpdump -U -i $INTERFACE -w $PCAP_FILENAME $TCPDUMP_FILTER 2>&1" & > /dev/null; then
        return 0 # success!
    else
        return 1
    fi
}


# -----------------------------------
# Sort tasklist by priority
# -----------------------------------
sort_tasklist() {
    TASK_HEADERS="priority,task_name,task_staus,scanner,extra_args"
    SORTED_TASKS=$(cat $TASK_FILE | grep -v 'priority,task_name' | sort)
    echo $TASK_HEADERS > $TASK_FILE
    echo "$SORTED_TASKS" >> $TASK_FILE
}


# -----------------------------------
# Scan function
# -----------------------------------
scan() {
    SCANNER=$1
    TARGET_HOST=$2
    OUTPUT_PATH=$3
    SCANNER_ARGS="$4" # must do something like ${4.<endline>}
    SCANNER_ARGS=$(echo $SCANNER_ARGS | sed 's/"//g')

    # Nmap
    if [ $SCANNER == "nmap" ]; then
        nmap -oX $OUTPUT_PATH.xml $TARGET_HOST $SCANNER_ARGS --system-dns 2>&1 > /dev/null &
        ERR_CODE=$?
        return $ERR_CODE

    # Zmap
    # elif [[ $SCANNER == "zmap" ]]; then
    #     zmap -i eth0 --probe-module=icmp_echoscan -G <MAC addr> <subnet> -o test.csv --output-fields=*
    fi
}


update_tasklist() {
    # Read through the tasks in the task file
    while IFS=, read -r PRIORITY TASK_NAME TASK_STATUS SCANNER EXTRA_ARGS
    do
        # Make sure that the task is not the header in the task file
        if [[ ! -z $TASK_NAME ]] && [[ $TASK_NAME != "task_name" ]]; then
            check_scan_status $TASK_NAME
            SCAN_STATUS=$?

            if [[ $SCAN_STATUS -eq 0 ]]; then
                if terminate_tcpdump $TASK_NAME; then
                    task_change $TASK_NAME $PRIORITY "ongoing" "completed"
#                    colored_message "green" "Capturing traffic on task \e[1m${TASK_NAME}\e[0m completed."
                else
                    colored_message "red" "Unable to terminate traffic capture on task \e[1m${TASK_NAME}\e[0m."
                fi
            fi
        fi
    done < $TASK_FILE
}

# -----------------------------------
# Read task list
# -----------------------------------
deploy_tasks_to_worker() {

    # Define worker host
    WORKER_HOST=$1

    # Read through the tasks in the task file
#    update_tasklist

    while IFS=, read -r PRIORITY TASK_NAME TASK_STATUS SCANNER EXTRA_ARGS
    do
        # Make sure that the task is not the header in the task file
        if [[ ! -z $TASK_NAME ]] && [[ $TASK_NAME != "task_name" ]]; then

            # Do not scan the management side
            TARGET_HOST=$(echo $WORKER_HOST | sed 's/-mng//g')
            # -------------------
            # Task status: NEW - deploy tasks to worker
            # -------------------
            if [[ $TASK_STATUS == "new" ]]; then
                TIMESTAMP=$(date +%Y%m%d%H%M)
                OUTPUT_PATH="${RESULT_DIR}/${TASK_NAME}_${TIMESTAMP}"

                # Start dumping traffic on a worker
                if start_tcpdump $WORKER_HOST "${TASK_NAME}_${TIMESTAMP}.pcap"; then
                    colored_message "green" "Capturing traffic on \e[1m${WORKER_HOST}\e[0m on task \e[1m${TASK_NAME}\e[0m"

                    # Start scan
                    sleep 3 # make sure tcpdump is spawned
                    if scan $SCANNER $TARGET_HOST $OUTPUT_PATH "$EXTRA_ARGS"; then
                        colored_message "green" "Scanning \e[1m${WORKER_HOST}\e[0m on task \e[1m${TASK_NAME}\e[0m"

                        # Change the task status
                        task_change $TASK_NAME $PRIORITY "new" "ongoing"
                    else
                        colored_message "red" "Unable to scan \e[1m${TARGET_HOST}\e[0m on task \e[1m${TASK_NAME}\e[0m"
                    fi
                else
                    colored_message "red" "Unable to capture traffic on \e[1m${WORKER_HOST}\e[0m on task \e[1m${TASK_NAME}\e[0m"
                    break
                fi 

                echo "" > /dev/null # for the fun of it
                break # break out since the worker already have received a task
#             elif [[ $TASK_STATUS == "ongoing" ]]; then
#                 check_scan_status $TASK_NAME
#                 SCAN_STATUS=$?

#                 if [[ $SCAN_STATUS -eq 0 ]]; then
#                     if terminate_tcpdump $TASK_NAME; then
#                         task_change $TASK_NAME $PRIORITY "ongoing" "completed"
# #                        colored_message "green" "Capturing traffic on task \e[1m${TASK_NAME}\e[0m completed."
#                     else
#                         colored_message "red" "Unable to terminate traffic capture on task \e[1m${TASK_NAME}\e[0m."
#                     fi
#                 fi
            fi
        fi
    done < $TASK_FILE
    sleep 5
}


# -----------------------------------
# Crawl through workers, check availability and deploy tasks
# -----------------------------------
#update_tasklist

for WORKER_HOST in ${WORKER_HOSTS[@]};
do

    # Check if the host is available for work
    available_worker $WORKER_HOST
    ERR_CODE=$?

    # available for work
    if [[ $ERR_CODE -eq 0 ]]; then
        colored_message "green" "$WORKER_HOST is available."
        deploy_tasks_to_worker $WORKER_HOST


    # unreachable
    elif [[ $ERR_CODE -eq 2 ]]; then
        colored_message "red" "$WORKER_HOST is unreachable (error code: $ERR_CODE)"

    # unavailable (working on something)
    elif [[ $ERR_CODE -eq 1 ]]; then
        echo "$WORKER_HOST is busy (error code: $ERR_CODE)."
#        deploy_tasks_to_worker $WORKER_HOST # checking scan status and updating status from ongoing to completed happens here
    fi


    # Kill all tcpdump processes on workers (useful during testing)
    # TASK_NAME=$(get_task_name $WORKER_HOST)
    # terminate_tcpdump $TASK_NAME
done
