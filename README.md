# IPK-SNIFFER Project Documentation

### Obsah

  - Představení projektu
  - Teorie a důležité kocenpty
  - Struktura kódu
  - Testování
  - Zdroje

# Představení projetku
Cílem projektu bylo vyvotvyřit síťový analyzátor, známý též jako 'network sniffer', který bude schopen zachytávat a filtrovat pakety na konkrétním síťovém rozhraní.

# Teorie a důležité kocenpty

 - Funkce a účel: Síťový analyzátor slouží k monitorování a analýze síťové komunikace. Jeho účelem je zachytávat, analyzovat a interpretovat pakety dat, které procházejí přes síťové rozhraní.
 - Zachytávání dat: Síťový analyzátor pasivně zachytává data, která putují po síti. To může zahrnovat data z různých protokolů, jako jsou například TCP/IP, UDP, HTTP, FTP atd.
 - Promiskuitní režim: Jednou z důležitých vlastností síťových analyzátorů je schopnost pracovat v promiskuitním režimu, což znamená, že mohou zachytávat a analyzovat veškerou síťovou komunikaci, i když není adresována konkrétnímu síťovému rozhraní.
 - Filtry a pravidla: Síťové analyzátory často umožňují použití filtrů a pravidel, aby uživatel mohl selektivně zachytávat a analyzovat pouze určité typy datových paketů nebo komunikaci mezi určitými zařízeními.
 - Protokolová analýza: Síťové analyzátory jsou schopny provádět hloubkovou analýzu různých síťových protokolů, což umožňuje identifikovat komunikační chyby, zabezpečení problémy nebo anomálie v síťovém provozu.
 - Bezpečnostní aplikace: Síťové analyzátory jsou často využívány v bezpečnostních aplikacích k detekci útoků, odhalování zranitelností a sledování síťového provozu pro účely bezpečnostního auditu a monitorování.

# Struktura kódu a základní použití

### Základní použití

Implementovaný `ipk-sniffer` podporuje následující list argumentů:

 - `-h` pro výpis použití
 - `-i | --interface [interface_name]` specifikaci rozhraní
 - `-n [number]` počet packetů pro zachycení (pokud není zádán zobrazí se vždy pouze jeden packet)
 - `-p [port_number]` port pro filtrování
 - `--port-destination [port_number]` zachytí packety s cílovým portem
 - `--port-source [port_number]` zachytí packety s zdrojovým portem
 - `-t | --tcp` zobrazí pouze TCP segmenty
 - `-u | --udp` zobrazí pouze UDP datagramy
 - `--icmp4` zobrazí pouze ICMPv4 packety
 - `--icmp6` zobrazí pouze ICMPv6 zprávy, které jsou typz ` echo request, echo reply`
 - `--arp` zobrází pouze `ARP`(Address Resolution Protocol) rámce
 - `--ndp` zobrazí pouze NDP (Neighbor Discovery Protocol) pakety, což je podmnožina ICMPv6
 - `--igmp` zobrazí pouze IGMP (Internet Group Management Protocol) pakety
 - `--mld` zobrazí pouze MLD (Multicast Listener Discovery) pakety

Argument `-i` musí být vždy zastoupen a společně s argumentem `-n` neomezují výběr typu zobrazených dat. 
Všechny ostatní argumenty omezují jej omezují. Dále argumenty typu `port`
rozšiřují specifikovaný/é argumenty `-t | --tcp` a `-u | --udp`. Pokud není specifikován argument `-t | --tcp` a `-u | --udp` a je specifikovan argument `-p | --port-destination | --port-source` je program ukončen.

    ./ipk-snifer [-i interface | --interface interface]  {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}




### Struktura kódu

Kód je rozdělen do 3 hlavních částí:

- `main`
- `prints`
- `filterBuilder`

Část `main` se stará o řízení programu, jsou z ní volány potřebné funkce z dalších částí. Nejdříve je z části `filterBuilder` zavolána funkce `filterBuilder`, která se zpracuje argumety, nastaví potřebné proměnné pro pozdější výpis a sestaví filtr pro zachytavání dat. Následně o řízení zachycování dat se starají funkce `createPcapHandle`, `stopCapture` a `startCapture`. 
Kde `cratePcapHandle` nastaví rozhraní a připravený filtr pro zachytavání dat pomocí funkcí `pcap_openlive()`, `pcap_findalldevs()`, `pcap_lookupnet()`. Dále `startCapture` zachytává data zpracovává je pomocí funkce `pcap_loop()`, která zachytí několik packtů a ty postupně předává funkci 
`processPacket`, která je dále roztřídí a případně výpíše, pomocí funkcí z 'printPackt' a dalších z části `prints` . Až je zpracován daný počet packetů nebo dojde k ukončení uživatelem `C^c` je program ukončen. 

# Testování

K testování jsem využil, komunitní testy, které byly ve formě python skriptu a program Wireshark.

### Krátký příklad testování:


Test 1:

    $ ./ipk24chat-client -t tcp -s 127.0.0.1 
    ..Sent 1 packets.
    timestamp: 2024-04-22T21:42:20.454203+01:00
    src MAC: 00:00:00:00:00:00
    dst MAC: ff:ff:ff:ff:ff:ff
    frame length: 73 bytes
    src IP: ::1
    dst IP: ::1
    
    0x0000   ff ff ff ff ff ff 00 00  00 00 00 00 86 dd 60 00    ..............`.
    0x0010   00 00 00 13 3a 40 00 00  00 00 00 00 00 00 00 00    ....:@..........
    0x0020   00 00 00 00 00 01 00 00  00 00 00 00 00 00 00 00    ................
    0x0030   00 00 00 00 00 01 80 00  7b 37 00 00 00 00 48 65    ........{7....He
    0x0040   6c 6c 6f 20 49 50 76 36  21                         llo IPv6!
    
    Packet statistics: 
    4 packets received
    0 packets dropped

Test 2:

    ..
    Sent 1 packets.
    timestamp: 2024-04-22T21:42:23.824201+01:00
    src MAC: 00:00:00:00:00:00
    dst MAC: ff:ff:ff:ff:ff:ff
    frame length: 78 bytes
    src IP: ::+
    dst IP: ::1
    
    0x0000   ff ff ff ff ff ff 00 00  00 00 00 00 86 dd 60 00    ..............`.
    0x0010   00 00 00 18 3a ff 00 00  00 00 00 00 00 00 00 00    ....:...........
    0x0020   00 00 00 00 00 01 00 00  00 00 00 00 00 00 00 00    ................
    0x0030   00 00 00 00 00 01 87 00  78 aa 00 00 00 00 00 00    ........x.......
    0x0040   00 00 00 00 00 00 00 00  00 00 00 00 00 01          ..............
    
    Packet statistics:
    4 packets received
    0 packets dropped

Test 3:
    
    ..
    Sent 1 packets.
    timestamp: 2024-04-22T21:42:27.174391+01:00
    src MAC: 00:00:00:00:00:00
    dst MAC: ff:ff:ff:ff:ff:ff
    frame length: 62 bytes
    src IP: ::1
    dst IP: ::1
    
    0x0000   ff ff ff ff ff ff 00 00  00 00 00 00 86 dd 60 00    ..............`.
    0x0010   00 00 00 08 3a ff 00 00  00 00 00 00 00 00 00 00    ....:...........
    0x0020   00 00 00 00 00 01 00 00  00 00 00 00 00 00 00 00    ................
    0x0030   00 00 00 00 00 01 85 00  7a bb 00 00 00 00          ........z.....
    
    Packet statistics:
    2 packets received
    0 packets dropped

Test 4:

    ..
    Sent 1 packets.
    timestamp: 2024-04-22T21:42:31.494212+01:00
    src MAC: 00:00:00:00:00:00
    dst MAC: ff:ff:ff:ff:ff:ff
    frame length: 89 bytes
    src IP: 127.0.0.1
    dst IP: 127.0.0.1
    src port: 20
    dst port: 4567
    
    0x0000   ff ff ff ff ff ff 00 00  00 00 00 00 08 00 45 00    ..............E.
    0x0010   00 4b 00 01 00 00 40 06  7c aa 7f 00 00 01 7f 00    .K....@.|.......
    0x0020   00 01 00 14 11 d7 00 00  00 00 00 00 00 00 50 02    ..............P.
    0x0030   20 00 84 70 00 00 47 45  54 20 2f 20 48 54 54 50     ..p..GET / HTTP
    0x0040   2f 31 2e 31 0d 0a 48 6f  73 74 3a 20 6c 6f 63 61    /1.1..Host: loca
    0x0050   6c 68 6f 73 74 0d 0a 0d  0a                         lhost....
    
    Packet statistics:
    2 packets received
    0 packets dropped

Test 5:

    ..
    Sent 1 packets.
    timestamp: 2024-04-22T21:42:34.934379+01:00
    src MAC: 00:00:00:00:00:00
    dst MAC: ff:ff:ff:ff:ff:ff
    frame length: 50 bytes
    src IP: 127.0.0.1
    dst IP: 127.0.0.1
    src port: 1234
    dst port: 1234
    
    0x0000   ff ff ff ff ff ff 00 00  00 00 00 00 08 00 45 00    ..............E.
    0x0010   00 24 00 01 00 00 40 11  7c c6 7f 00 00 01 7f 00    .$....@.|.......
    0x0020   00 01 00 35 04 d2 00 10  d0 45 54 65 73 74 20 55    ...5.....ETest U
    0x0030   44 50                                               DP
    Packet statistics:
    2 packets received
    0 packets dropped


# Zdroje
* https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/
* RFC 792 - Internet Control Message Protocol a RFC 4443 - ICMPv6
* RFC 5952 - A Recommendation for IPv6 Address Text Representation
* RFC 3339 -  Date and Time on the Internet: Timestamps
* Wikipedia, the free encyclopedia: http://en.wikipedia.org/wiki/Pcap
* https://www.tcpdump.org
* https://en.wikipedia.org/wiki/ICMPv6
* https://stackoverflow.com
* http://yuba.stanford.edu/~casado/pcap/section1.html