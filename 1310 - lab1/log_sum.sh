#! /bin/bash

# fields in the log file describe the following:
# 1. The IP number the request originated from.
# 2. The ident answer from the originator (always ’-’).
# 3. The username of the requester, as determined by http authentication.
# 4. The date and time the request was processed.
# 5. The request line as it was received from the client, in double quotes.
# 6. The http status code that was sent to the client.
# 7. The number of bytes that were transferred to the client.
# 8. The referrer page (from the client).
# 9. The user agent string (from the client).

# Example line:
# 172.16.0.3 - - [31/Mar/2002:19:30:41 +0200] "GET / HTTP/1.1" 200 123 "" "Mozilla/5.0 (compatible; Konqueror/2.2.2-2; Linux)"
#       1    2 3            4                          5        6   7  8                        9


# By accessing the information in the web server log file, your script (which must be named log sum.sh) should be able to answer the following questions:
# • Which IP addresses makes the most number of connection attempts
# • Which IP addresses makes the most number of successful connection attempts?
# • What are the most common result codes, and where do they come from? (i.e. from which IP number).
# • What are the most common result codes that indicate failure (i.e. no authentication, not found, etc.) and where do they come from?
# • Which IP number get the most bytes sent to them?

function most_connection_ip {

    if [ $IP_CAP != '' ]; then
        #alt cat "$FILE_PATH" | awk 'BEGIN{FS=" "} { print $1 }' | uniq -c | sort -n -r | awk 'BEGIN{FS=" "} { print $2 " " $1 }' | head -n "$IP_CAP"
        grep -E -o "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" "$FILE_PATH" | sort | uniq -c | sort -n -r | head -n "$IP_CAP" | awk 'BEGIN{FS=" "} { print $2 " " $1 }'
    else
        #alt cat "$FILE_PATH" | awk 'BEGIN{FS=" "} { print $1 }' | uniq -c | sort -n -r | awk 'BEGIN{FS=" "} { print $2 " " $1 }'
        grep -E -o "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" "$FILE_PATH" | sort | uniq -c | sort -n -r | awk 'BEGIN{FS=" "} { print $2 " " $1 }'
    fi
}

function get_succesful_attempts {

    if [ $IP_CAP != '' ]; then
        cat "$FILE_PATH" | awk 'BEGIN{FS=" "} { print $1 " " $9 }' | grep -E "\ ([2][0-9][0-9])" | awk 'BEGIN{FS=" "} { print $1}' | sort | uniq -c | awk 'BEGIN{FS=" "} { print $2 " " $1 }' | head -n "$IP_CAP"
    else
        cat "$FILE_PATH" | awk 'BEGIN{FS=" "} { print $1 " " $9 }' | grep -E "\ ([2][0-9][0-9])" | awk 'BEGIN{FS=" "} { print $1}' | sort | uniq -c | awk 'BEGIN{FS=" "} { print $2 " " $1 }'
    fi
    
}

function most_common_res_codes {
    common_res_codes=($(cat "$FILE_PATH" | awk 'BEGIN{FS=" "} { print $9 }' | sort | uniq -c | sort -n -r | awk 'BEGIN{FS=" "} { print $2 }'))
    
    HEAD_PARAM="-n -0"
    if [ $IP_CAP != "" ]; then
        HEAD_PARAM="-n $IP_CAP"
    fi

    for code in ${common_res_codes[@]}; do
        cat "$FILE_PATH" | awk -v code="$code" 'BEGIN{FS=" "} $9==code { print $1 }' | sort | uniq -c | sort -n -r | awk -v code="$code" 'BEGIN{FS=" "} { print code " " $2}' | head $HEAD_PARAM
        printf "\n"
    done 
        
}

function res_codes_failure {
    # return most common error codes in array (sorted by most accurances)
    sorted_codes=$(cat "$FILE_PATH" | awk 'BEGIN{FS=" "} { print $9 }' | sort | uniq -c | sort -n -r | grep -E "\ ([4-5][0-9][0-9])" | awk 'BEGIN{FS=" "} { print $2 }')

    HEAD_PARAM="-n -0"
    if [ $IP_CAP != "" ]; then
        HEAD_PARAM="-n $IP_CAP"
    fi
     # for each found error code in file, look for requests with mathcing code
    for i in ${sorted_codes[@]}; do
        cat "$FILE_PATH" | awk 'BEGIN{FS=" "} { print $9 " " $1}' | grep "$i\ " | sort | uniq -c | sort -nr | awk 'BEGIN{FS=" "} { print $2 " " $3}' | head $HEAD_PARAM
        printf "\n"
    done
}

function most_byte_sent_ip {
    iplist=($(cat "$FILE_PATH" | cut -d ' ' -f 1,10 | sort -t ' '))
    # awk -v ip="62.13.65.12" 'sum+=$2, ip==$1 {} END{print sum}'
    unique_ip=($(cat "$FILE_PATH" | awk 'BEGIN{FS=" "} { print $1 }' | sort | uniq))
    for ip in ${unique_ip[@]}; do
        awk -v ip="$ip" 'sum+=$2, ip==$1 {} END{print sum " " ip}'
    done

    IP_VAR=''
    IP_LINE_VAR=''
    BYTE_VAR=0
    BYTE_LINE_VAR=0
    iplist2=''
    echo ${iplist[1]}  # ${#a[@]}
    for i in range(1..${#iplist[@]})
    do
        
    done
    for line in $iplist
    do
        IP_LINE_VAR=$(echo $line | cut -d ' ' -f 1)
        BYTE_LINE_VAR=$(echo $line | cut -d ' ' -f 2 | grep -v '-')
        if [[ $IP_VAR == '' ]]; then
            IP_VAR=$IP_LINE_VAR
        elif [[ $IP_VAR != $IP_LINE_VAR ]]; then
            iplist2+=($IP_VAR+" "+$BYTE_VAR)
            IP_VAR=$IP_LINE_VAR
        fi
        BYTE_VAR=$(expr $BYTE_VAR+$BYTE_LINE_VAR)
    done

    echo "$iplist2"
}

IP_CAP=""
ARG_FLAG="$1"
FILE_PATH="${@: -1}" #filepath

if [ "$#" -gt 5 ]; then
    echo "Too many arguments."
    exit 1
elif [ "$#" -lt 2 ]; then
    echo "Too few arguments."
    exit 1
elif [ "$1" = "-L" ]; then
    IP_CAP="$2"
    ARG_FLAG="$3"
fi

case $ARG_FLAG in
    -c) most_connection_ip;;
    -2) get_succesful_attempts;;
    -r) most_common_res_codes;;
    -F) res_codes_failure;;
    -t) most_byte_sent_ip;;
    *) echo "No valid flag specified.";;
esac

# while getopts "okc" option ; do
# case $option in
# o) echo " Exporting OS information . " ;
# echo " Operative system : $ ( uname -o ) " > OS_info . txt ;
# echo " Distribution : $ ( uname -n ) " >> OS_info . txt ;
# echo " Architecture : $ ( uname -m ) " >> OS_info . txt ;;
# k) echo " Exporting Kenel information . " ;
# echo " Kernel : $ ( uname -s ) " > Kernel_info . txt ;
# echo " Release Version : $ ( uname -r ) " >> Kernel_info . txt ;;
# c) echo " Exporting CPU information . " ;
# cat / proc / cpuinfo > CPU_info . txt ;;
# *) echo " Error : An invalid argument has been given . Only use -o
# -k or -c as arguments . " ;;
# esac
# done



