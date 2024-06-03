# 2. projekt IPK, Varianta ZETA: Sniffer paketů
Autor: Simona Češková (xcesko00)\
Datum: 24.04.2022
## Popis projektu:
Projekt vytváří komunikující aplikaci, podle vybrané specifikace za použití knihovny libcap, nebo BSD socket. Tato aplikace je síťový analyzátor, který je schopný naurčitém síťovém rozhraní zachytávat a filtrovat pakety.
## Způsob zpuštění projektu:
### Kompilace
Pro kompilaci zdrojového kódu je možné použít `Makefile` příkazem `make`.
### Spouštění
Pro spuštění je třeba do příkazové řádky uvést příkaz:\
`sudo ./ipk-sniffer [-i rozhrani | --interface]{-p port}{[--tcp|-t][--udp|-u][--arp][--icmp]}{-n num}`
## Jednotlivé parametry:
- `-i|--interface rozhrani` udává v jakém rozhraní bude probíhat přenos dat. Při nezadání parametrů, nebo jeho argumentů se vypíše list možných použitelných rozhraní.
- `-p port` uvádá číslo platného portu, pokud není parametr zadán, tak bude přenos v rozmezí 0-65535
- `--tcp|-t, --udp|-u, --arp, --icmp` při nezadání ani jednoho parametru se automaticky vyberou všechny. Je možno zadat více protokolů zároveň.
- `-n num` počet paket, který se vypíše na stdin. Při nezadání je automaticky roven jedné.
## Výstup:
Výstupem je paketa, která obsahuje informace o sobě, podle toho na jakém protokolu se nachází.
`timestamp:` čas přenosu\
`src MAC:` MAC adresa odesílatele\
`dst MAC:` MAC adresa přijímatele\
`frame length: bytes` velikost pakety v bytech\
`src IP: ` IP adresa odesílatele\
`dst IP: ` IP adresa přijímatele\
`src port: ` číslo portu odesílatele\
`dst port:` číslo portu přijímatele\
-hexadecimální zápis dat pakety

## Ukončení zachytávání a filtrace paket:
Ukončení pomocí `ctrl + C` v terminálu, kde byl program spuštěn.
## Licence:
Licence na použití, převzaná ze zdroje, který obsahuje pasáž použitého kódu. Více informací v dokumentaci. \ \
sniffex.c\ \
Sniffer example of TCP/IP packet capture using libpcap.\ \
Version 0.1.1 (2005-07-05)\
Copyright (c) 2005 The Tcpdump Group\ \
This software is intended to be used as a practical example and\
demonstration of the libpcap library; available at:\ \
http://www.tcpdump.org/


