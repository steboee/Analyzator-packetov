import binascii

import dpkt

from contextlib import redirect_stdout
import os
import binascii
class PACKETList(list):

    def __init__(self, iterable=None):
        """Override initializer which can accept iterable"""
        super(PACKETList, self).__init__()
        if iterable:
            for item in iterable:
                self.append(item)

    def append(self, item):
        if isinstance(item, PACKET):
            super(PACKETList, self).append(item)
        else:
            raise ValueError('Ghosts allowed only')

    def insert(self, index, item):
        if isinstance(item, PACKET):
            super(PACKETList, self).insert(index, item)
        else:
            raise ValueError('Ghosts allowed only')

    def __add__(self, item):
        if isinstance(item, PACKET):
            super(PACKETList, self).__add__(item)
        else:
            raise ValueError('Ghosts allowed only')

    def __iadd__(self, item):
        if isinstance(item, PACKET):
            super(PACKETList, self).__iadd__(item)
        else:
            raise ValueError('Ghosts allowed only')

class LLC_header:
    def __init__(self, DSAP, SSAP):
        self.SSAP = SSAP
        self.DSAP = DSAP
        self.fragmented = False
        self.protocol = None

    def vypis(self):
        print("SSAP: " + str(self.SSAP) + " "  + file_checker(self.SSAP, "+"))
        print("DSAP: " + str(self.DSAP))

class ARP_header:
    def __init__(self, Opcode, sender_MAC, sender_IP, target_MAC, target_IP):
        self.sender_MAC = sender_MAC
        self.sender_IP = sender_IP
        self.target_MAC = target_MAC
        self.target_IP = target_IP
        self.Opcode = Opcode
        self.fragmented = False
        self.protocol = None

    def vypis(self):
        print("Sender MAC address : " + str(self.sender_MAC))
        print("Sender IP address : " + str(self.sender_IP))
        print("Target MAC address : " + str(self.target_MAC))
        print("Target IP address : " + str(self.target_IP))

class IP_header:
    def __init__(self, protokol, source_adress, destination_adress, length):
        self.protocol = protokol
        self.source_adress = source_adress
        self.destination_adress = destination_adress
        self.length = length
        self.fragmented = False

    def vypis(self):
        print("Source IP address : " + self.source_adress)
        print("Destination IP address : " + self.destination_adress)

    def set_fragmented(self, type):
        self.fragmented = True
        self.icmp_fragmented_type = type

class TCP_header:
    def __init__(self, source_port, destination_port,flags):
        self.source_port = source_port
        self.destination_port = destination_port
        self.flag = flags[7:]
        self.flaglist = []
        if (self.flag[4] == "1"):
            self.flaglist.append("FIN")
        if (self.flag[3] == "1"):
            self.flaglist.append("SYN")
        if (self.flag[2] == "1"):
            self.flaglist.append("RST")
        if (self.flag[1] == "1"):
            self.flaglist.append("PSH")
        if (self.flag[0] == "1"):
            self.flaglist.append("ACK")


    def getName(self):
        return "TCP"

    def getInfo(self):
        return self.source_port, self.destination_port

    def vypis(self):
        print(
            "Source port : " + str(int(self.source_port, 16)) + "  (" + str(file_checker(self.source_port, "/")) + ")")
        print("Destination port : " + str(int(self.destination_port, 16)) + "  (" + str(
            file_checker(self.destination_port, "/")) + ")")

class ICMP_header:
    def __init__(self, type):
        self.type = type

    def getName(self):
        return "ICMP"

    def getInfo(self):
        return self.type

    def vypis(self):
        print("ICMP type : " + str(self.type[0]) + "  ( " + str(self.type[1]) + " )" + "\n")

class UDP_header:
    def __init__(self, source_port, destination_port):
        self.source_port = source_port
        self.destination_port = destination_port

    def getName(self):
        return "UDP"

    def getInfo(self):
        return self.source_port, self.destination_port

    def vypis(self):
        print(
            "Source port : " + str(int(self.source_port, 16)) + "  (" + str(file_checker(self.source_port, "<")) + ")")
        print("Destination port : " + str(int(self.destination_port, 16)) + "  (" + str(
            file_checker(self.destination_port, "<")) + ")")

mylist = PACKETList()


class PACKET:
    def __init__(self, position, length_real, length_media):
        self.position = position
        self.length_real = length_real
        self.length_media = length_media

    def set_text(self, ramec):
        self.ramec = ramec

    class Data_link_header:
        def __init__(self, destination_mac, source_mac, typ_prenosu):
            self.typ_prenosu = typ_prenosu
            self.source_mac = source_mac
            self.destination_mac = destination_mac

        def set_eth_type(self, protocol_type):
            self.eth_type = protocol_type

    class Protocol:
        def __init__(self):
            self.fragmented = False

        def getName(self):
            return "Unknown"

        def vypis(self):
            self.Protocol.vypis()


def length_of_packet_media(length):
    x = 0
    if (length < 60):
        x = 64
    else:
        x = length + 4
    return x

def dest_mac_adress(list_of_packet_bytes):
    destin = ""
    i = 0
    while (i != 5):
        destin = destin + str(list_of_packet_bytes[i]) + ":"
        i = i + 1
    destin = destin + str(list_of_packet_bytes[i])

    return destin

def source_mac_adress(list_of_packet_bytes):
    source = ""
    i = 6
    while (i != 11):
        source = source + str(list_of_packet_bytes[i]) + ":"
        i = i + 1
    source = source + str(list_of_packet_bytes[i])
    return source

def type_of_packet(whole_packet):
    a = whole_packet[12]
    b = whole_packet[13]
    c = a + b
    sum = int(c, 16)
    if sum >= 1536:
        type = "Ethernet II"
        # print(type)
    else:
        a = whole_packet[14]
        b = whole_packet[15]
        c = a + b
        # print(c)
        if (c == "ffff"):
            type = "IEEE 802.3 Novell RAW"
        else:
            if (c == "aaaa"):
                type = "IEEE 802.3 LLC + SNAP"
            else:
                type = "IEEE 802.3 LLC"

    return type

def file_checker(number, ID):
    number = int(number, 16)
    file = open('protocols', 'r')

    for riadok in file:
        if (riadok[0] == ID):
            riadok = riadok[1:]
            a = riadok.split("=")
            if (str(number) == a[0].strip()):
                return a[1].strip()

    file.close()
    return "Unknown"

def ARP_info(packet, whole_packet):
    Opcode = whole_packet[20] + whole_packet[21]
    Opcode = int(Opcode)
    Sender_mac = ""
    Sender_ip = ""
    Target_mac = ""
    Target_ip = ""
    i = 22
    while (i != 28):
        Sender_mac = Sender_mac + str(whole_packet[i]) + ":"
        i = i + 1
    while (i != 31):
        ip = whole_packet[i]
        ip = int(ip, 16)
        Sender_ip = Sender_ip + str(ip) + "."
        i = i + 1
    Sender_ip = Sender_ip + str(ip)
    i = i + 1
    while (i != 38):
        Target_mac = Target_mac + str(whole_packet[i]) + ":"
        i = i + 1
    while (i != 42):
        ip = whole_packet[i]
        ip = int(ip, 16)
        Target_ip = Target_ip + str(ip) + "."
        i = i + 1
    Target_ip = Target_ip + str(ip)
    i = i + 1
    arp = ARP_header(Opcode, Sender_mac, Sender_ip, Target_mac, Target_ip)
    return arp

def IP_info(packet, whole_packet):
    length = bin(int(whole_packet[14], 16))
    length = length[2:].zfill(8)
    length = length[4:]  # z pôvodneho 1B ponechám len pravú 1/2 -> Header Length of IPv4
    length = int(length, 2) * 4

    protocol_number = whole_packet[23]
    protocol = file_checker(protocol_number, "-")
    source_adress = ""
    destination_adress = ""

    i = 26
    while (i != 29):
        ip = whole_packet[i]
        ip = int(ip, 16)
        source_adress = source_adress + str(ip) + "."
        i = i + 1
    ip = whole_packet[i]
    ip = int(ip, 16)
    source_adress = source_adress + str(ip)
    i = i + 1

    while (i != 33):
        ip = whole_packet[i]
        ip = int(ip, 16)
        destination_adress = destination_adress + str(ip) + "."
        i = i + 1
    ip = whole_packet[i]
    ip = int(ip, 16)
    destination_adress = destination_adress + str(ip)

    i = length + 14
    if (protocol == "UDP"):

        # source_port = file_checker(whole_packet[i]+whole_packet[i+1],"<") + "   ->   "+ str(int(whole_packet[i] + whole_packet[i+1],16))
        # destination_port = file_checker(whole_packet[i+2]+whole_packet[i+3],"<") + "   ->   "+ str(int(whole_packet[i+2] + whole_packet[i+3],16))

        source_port = whole_packet[i] + whole_packet[i + 1]
        destination_port = whole_packet[i + 2] + whole_packet[i + 3]

        UDP = UDP_header(source_port, destination_port)
        IP = IP_header(UDP, source_adress, destination_adress, length)
        return IP

    elif (protocol == "TCP"):

        # source_port = file_checker(whole_packet[i] + whole_packet[i + 1], "/") + "   ->   "+ str(int(whole_packet[i] + whole_packet[i+1],16))
        # destination_port = file_checker(whole_packet[i + 2] + whole_packet[i + 3], "/") + "   ->   "+ str(int(whole_packet[i+2] + whole_packet[i+3],16))
        source_port = whole_packet[i] + whole_packet[i + 1]
        destination_port = whole_packet[i + 2] + whole_packet[i + 3]
        flag_section1 = whole_packet[i + 12][1]
        flag_section2 = whole_packet[i + 13][0]
        flag_section3 = whole_packet[i + 13][1]

        flag_section1 = bin(int(flag_section1, base=16)).lstrip('0b').zfill(4)
        flag_section2 = bin(int(flag_section2, base=16)).lstrip('0b').zfill(4)
        flag_section3 = bin(int(flag_section3, base=16)).lstrip('0b').zfill(4)

        flag = flag_section1 + flag_section2 + flag_section3

        TCP = TCP_header(source_port, destination_port,flag)
        IP = IP_header(TCP, source_adress, destination_adress, length)
        return IP

    elif (protocol == "ICMP"):
        a = mylist[len(mylist) - 2]
        if (type(a.Protocol) != str and a.Protocol != None):
            if (a.Protocol.fragmented == True):
                icmp_type = a.Protocol.icmp_fragmented_type
                ICMP = ICMP_header(icmp_type)
                IP = IP_header(ICMP, source_adress, destination_adress, length)
                return IP

        flags_num = int(whole_packet[20], 16)
        if (flags_num == 32):
            IP = IP_header("fragmented ICMP", source_adress, destination_adress, length)
            icmp_type = file_checker(whole_packet[i], ">")
            icmp_list = [icmp_type, int(whole_packet[34], 16)]
            IP.set_fragmented(icmp_list)
            return IP

        icmp_type = file_checker(whole_packet[i], ">")
        icmp_list = [icmp_type, int(whole_packet[i], 16)]
        ICMP = ICMP_header(icmp_list)
        IP = IP_header(ICMP, source_adress, destination_adress, length)
        return IP

    else:
        IP = IP_header(protocol, source_adress, destination_adress, length)
        return IP

def LoadAllPackets(pcap,mylist):
    position = 1
    for packet in pcap:
        media_length = length_of_packet_media(len(packet[1]))
        one_packet = PACKET(position, len(packet[1]), media_length)
        other = packet[1]
        counter_of_lines = 0   #pre vypis typ 0000 |
        riadok = ""
        counter = 0           #použitie: na vypis ramca aby sa vypisoval po 16 bytes
        whole_packet = []
        global text
        text = ""
        for x in other:
            if (counter == 0):
                riadok = "".join("{:02x}".format(x)) + " "

            elif (counter == 7):
                riadok = riadok + "".join("{:02x}".format(x)) + "   "

            elif (counter < 16):
                riadok = riadok + "".join("{:02x}".format(x)) + " "



            else:
                counter = 0                         # Reset counter na 0 --> nový riadok
                cislovanie_riadku = str(hex(counter_of_lines).lstrip("0x").rstrip("L"))      #spracovanie číslovanie riadku
                cislovanie_riadku = cislovanie_riadku.zfill(3)                  # doplnenie ne to aby mal 3 číslice
                cislovanie_riadku = cislovanie_riadku + "0"                     # pridať na koniec 0 -> tá sa nemení stále = 0

                text = text + (cislovanie_riadku + " |   " + riadok) + "\n"     # appendovanie nového riadku k celému textu
                counter_of_lines = counter_of_lines + 1                           # ideme na další riadok
                riadok = "".join("{:02x}".format(x)) + " "                      # formátovanie riadku na výpis : 00 04 96 ....

            counter = counter + 1
            a = "".join("{:02x}".format(x))
            whole_packet.append(a)                                              # list whole_packet reprezentuje list bytov daného ramca v hex

        cislovanie_riadku = str(hex(counter_of_lines).lstrip("0x").rstrip("L"))
        cislovanie_riadku = cislovanie_riadku.zfill(3)
        cislovanie_riadku = cislovanie_riadku + "0"
        text = text + (cislovanie_riadku + " |   " + riadok) + "\n"

        mylist.append(one_packet)

        src = source_mac_adress(whole_packet)
        dst = dest_mac_adress(whole_packet)

        typ_prenosu = type_of_packet(whole_packet)

        one_packet.Data_link_header = one_packet.Data_link_header(dst, src, typ_prenosu)

        if (typ_prenosu == "Ethernet II"):

            protokol_number = whole_packet[12] + whole_packet[13]
            ETHTYPE = file_checker(protokol_number, "|")  # hex číslo protokolu a špec. znak (určuje aký typ chcem hľadať)
            ethtyp = [ETHTYPE, protokol_number]
            one_packet.Data_link_header.set_eth_type(ethtyp)

            if (one_packet.Data_link_header.eth_type[0] == "ARP"):
                protocol = ARP_info(one_packet, whole_packet)
                one_packet.Protocol = protocol

            elif (one_packet.Data_link_header.eth_type[0] == "IPv4"):
                protocol = IP_info(one_packet, whole_packet)
                one_packet.Protocol = protocol


            else:
                protocol = None
                one_packet.Protocol = protocol

        else:

            IEEE = LLC_header(whole_packet[14], whole_packet[15])
            one_packet.Protocol = IEEE
            if (typ_prenosu == "IEEE 802.3 LLC + SNAP"):
                protokol_number = whole_packet[20] + whole_packet[21]
                ETHTYP = file_checker(whole_packet[20] + whole_packet[21], "|")

                ethtyp = [ETHTYP, int(protokol_number, 16)]
                one_packet.Data_link_header.set_eth_type(ethtyp)
            elif (typ_prenosu == "IEEE 802.3 Novell RAW"):
                one_packet.Data_link_header.set_eth_type(["IPX",""])
            else:
                one_packet.Data_link_header.set_eth_type(None)


        one_packet.set_text(text)

        position = position + 1





def communication(source,listpacketov):
    list_komunikacie = []
    for i in range(len(listpacketov)):
        if (int(listpacketov[i].Protocol.protocol.source_port,16) == source or int(listpacketov[i].Protocol.protocol.destination_port,16) == source):
            list_komunikacie.append(listpacketov[i])
        else:
            pass


    out = [source,list_komunikacie]
    return out

def option_1(list):
    num_of_packets = list.__len__()
    with open('program_output.txt', 'w') as outp:
        with redirect_stdout(outp):
            print("----------------------PRINTING PACKETS-----------------------------\n\n")
            for i in range(num_of_packets):
                print_p(list[i])

            ip_addresses = [[], []]
            i = 0
            j = 0
            for i in range(num_of_packets):
                if (list[i].Data_link_header.eth_type != None):

                    if (list[i].Data_link_header.eth_type[0] == "IPv4"):

                        if (type(list[i].Protocol.protocol) != str):

                            if (list[i].Protocol.protocol.getName() == "TCP"):

                                if (list[i].Protocol.source_adress in ip_addresses[0]):
                                    index = ip_addresses[0].index(list[i].Protocol.source_adress)
                                    ip_addresses[1][index] = ip_addresses[1][index] + 1

                                else:
                                    ip_addresses[0].append(list[i].Protocol.source_adress)
                                    index = ip_addresses[0].index(list[i].Protocol.source_adress)
                                    ip_addresses[1].append(1)
                i = i + 1

            print("Zoznam IP adries všetkých odosielajúcich uzlov : ")
            for j in range(len(ip_addresses[1])):
                print(ip_addresses[0][j])
            if (len(ip_addresses[0]) == 0):
                print("V súbore neboli protokoly rodiny TCP/IPv4 ")
            else:
                print("\nNajviac packetov odoslala IP : ")
                most = max(ip_addresses[1])
                index = ip_addresses[1].index(most)
                print(str(ip_addresses[0][index]) + " - " + str(most))

def option_2(list, keyword):
    there_are = False
    num_of_packets = list.__len__()
    if (keyword == "TFTP"):
        family = "UDP"
        symbol = "<"
    else:
        family = "TCP"
        symbol = "/"

    key_number = ""
    with open('program_output.txt', 'w') as outp:
        with redirect_stdout(outp):
            listpacketov = []

            for i in range(num_of_packets):
                if (list[i].Data_link_header.eth_type != None):
                    protokol = list[i].Data_link_header.eth_type[0]
                    if (protokol == "IPv4"):

                        if (type(list[i].Protocol.protocol) != str):

                            if (list[i].Protocol.protocol.getName() == family):
                                a = list[i].Protocol.protocol.getInfo()
                                source = file_checker(a[0], symbol)
                                destination = file_checker(a[1], symbol)

                                if (destination == keyword):
                                    listpacketov.append(list[i])
                                    if (key_number == ""):
                                        key_number = a[1]

                                elif( source == keyword):
                                    listpacketov.append(list[i])
                                    if (key_number == ""):
                                        key_number = a[0]


                i = i + 1

            # zhromaždenie packetov obsahujúcich daný port. -> listpacketov
            # -------------------------------------------------------------------------------------------------------------------------------------------------------- #
            streams = []
            key_protocol = int(a[0],16)
            source_list = []
            for packet in listpacketov:
                if (int(packet.Protocol.protocol.source_port,16) != int(key_number,16)):
                    source = int(packet.Protocol.protocol.source_port, 16)
                    if (len(streams) != 0):
                        if (source in source_list):
                            pass
                        else:
                            com = communication(source, listpacketov)
                            source_list.append(source)
                            streams.append(com)

                    else:
                        com = communication(source, listpacketov)
                        source_list.append(source)
                        streams.append(com)

            print("THERE are totally : " + str(len(streams)) + " communication for " + str(keyword) + "\n\n")

            if (len(streams) > 0):
                i = 1
                complet = 0
                incomplete = 0
                for stream in streams:
                    # print("KOMUNIKÁCIA Č. " + str(i) + "\n")    # na výpis všetkých komunikacií
                    # i = i + 1
                    if ("SYN" in stream[1][0].Protocol.protocol.flaglist and stream[1][0].Protocol.protocol.source_port != key_number):
                        if ("SYN" in stream[1][1].Protocol.protocol.flaglist and "ACK" in stream[1][1].Protocol.protocol.flaglist and stream[1][1].Protocol.protocol.source_port == key_number):
                            if ("ACK" in stream[1][2].Protocol.protocol.flaglist and stream[1][2].Protocol.protocol.source_port != key_number):
                                dlzka = len(stream[1])
                                if ("RST" in stream[1][dlzka-1].Protocol.protocol.flaglist):
                                    if (complet != 1):
                                        print("Prvá kompletná komunikácia " ) #+ str(i) + "\n")  # na výpis všetkých komunikacií
                                        i = i + 1
                                        print_communication(stream[1])
                                        complet = 1

                                elif ("FIN" in stream[1][dlzka-4].Protocol.protocol.flaglist and stream[1][dlzka-4].Protocol.protocol.source_port == key_number):
                                    if ("ACK" in stream[1][dlzka-3].Protocol.protocol.flaglist and stream[1][dlzka-3].Protocol.protocol.source_port != key_number):
                                        if ("FIN" in stream[1][dlzka-2].Protocol.protocol.flaglist and stream[1][dlzka-2].Protocol.protocol.source_port != key_number):
                                            if ("ACK" in stream[1][dlzka-1].Protocol.protocol.flaglist and stream[1][dlzka-1].Protocol.protocol.source_port == key_number):
                                                if (complet != 1):
                                                    print("Prvá kompletná komunikácia ") # + str(i) + "\n")  # na výpis všetkých komunikacií
                                                    i = i + 1
                                                    print_communication(stream[1])
                                                    complet = 1
                                else:
                                    if (incomplete != 1):
                                        print("Prvá nekompletná komunikácia ") # + str(i) + "\n")  # na výpis všetkých komunikacií
                                        i = i + 1
                                        print_communication(stream[1])
                                        incomplete = 1





                    #for packet in stream[1]:
                     #   print_communication(packet)
                    #print("\n")







def print_communication(stream):

    if (len(stream) <= 20):
        for packet in stream:
            print("#." + str(packet.position).zfill(3) +
                  "   " + str(packet.Protocol.source_adress) +
                  " -> " + str(packet.Protocol.destination_adress) +
                  "  (" + str(int(packet.Protocol.protocol.source_port, 16)) +
                  " -> " + str(int(packet.Protocol.protocol.destination_port, 16)) + ")" +
                  "  " + str(packet.Protocol.protocol.flaglist))
        print("\n")
    else:
        count = 0
        while (count != 10):
            print("#." + str(stream[count].position).zfill(3) +
                  "   " + str(stream[count].Protocol.source_adress) +
                  " -> " + str(stream[count].Protocol.destination_adress) +
                  "  (" + str(int(stream[count].Protocol.protocol.source_port, 16)) +
                  " -> " + str(int(stream[count].Protocol.protocol.destination_port, 16)) + ")" +
                  "  " + str(stream[count].Protocol.protocol.flaglist))
            count = count + 1
        print("\n........\n")

        dlzka = len(stream)
        while(count != 0):

            print("#." + str(stream[dlzka-count].position).zfill(3) +
                  "   " + str(stream[dlzka-count].Protocol.source_adress) +
                  " -> " + str(stream[dlzka-count].Protocol.destination_adress) +
                  "  (" + str(int(stream[dlzka-count].Protocol.protocol.source_port, 16)) +
                  " -> " + str(int(stream[dlzka-count].Protocol.protocol.destination_port, 16)) + ")" +
                  "  " + str(stream[dlzka-count].Protocol.protocol.flaglist))
            count = count - 1
        print("\n")


def option_3(list):
    num_of_packets = list.__len__()

    for i in range(num_of_packets):
        with open('program_output.txt', 'w') as outp:
            with redirect_stdout(outp):
                if (list[i].Data_link_header.eth_type[0] == "IPv4"):
                    if (type(list[i].Protocol.protocol) != str):
                        if (list[i].Protocol):
                            pass




#Funkcia na výpis packetu (bod_1)
def print_p(packet):
    print("--------------------------------PACKET_" + str(packet.position) + "----------------------------------\n")
    print("Length of packet : " + str(packet.length_real) + " B")
    print("Length of packet through media : " + str(packet.length_media) + " B")
    print(packet.Data_link_header.typ_prenosu + "\n")
    print("Destination MAC address: " + packet.Data_link_header.destination_mac)
    print("Source MAC address: " + packet.Data_link_header.source_mac + "\n")
    if (packet.Data_link_header.eth_type == None):                                          #IEEE 802.3 LLC /RAW
        print("Nested Protocol: NONE")
    else:
        print("Nested Protocol: " + str(packet.Data_link_header.eth_type[0]) + "   " + str(
            packet.Data_link_header.eth_type[1]))

    if (packet.Protocol != None):
            packet.Protocol.vypis()
            if (type(packet.Protocol.protocol) == str):
                print(packet.Protocol.protocol)
            elif (packet.Protocol.protocol != None):
                print(packet.Protocol.protocol.getName())
                packet.Protocol.protocol.vypis()

    print("")
    print(packet.ramec)
    print("\n----------------------------END OF PACKET_" + str(packet.position) + "-------------------------------\n\n\n\n")






#Prints the menu of progran
def print_menu():
    print("--------------------")
    print("Analyzátor packetov")
    print("--------------------\n")
    print("Po stlačení 0 ukončí program ")
    print("Po stlačení 1 vypíše všetky komunikácie -> bod zo zadania : 1.a), 1.b), 1.c), 1.d) , 2, 3 ")
    print("Po stlačení 2 vypíše všetky komunikácie pre HTTP -> bod zo zadania : 4.a) ")
    print("Po stlačení 3 vypíše všetky komunikácie pre HTTPS -> bod zo zadania : 4.b) ")
    print("Po stlačení 4 vypíše všetky komunikácie pre TELNET -> bod zo zadania : 4.c) ")
    print("Po stlačení 5 vypíše všetky komunikácie pre SSH -> bod zo zadania : 4.d) ")
    print("Po stlačení 6 vypíše všetky komunikácie pre FTP Control -> bod zo zadania : 4.e) ")
    print("Po stlačení 7 vypíše všetky komunikácie pre FTP Data -> bod zo zadania : 4.f) ")
    print("Po stlačení 8 vypíše všetky komunikácie pre TFTP -> bod zo zadania : 4.g) ")
    print("Po stlačení 9 vypíše všetky komunikácie pre ICMP -> bod zo zadania : 4.h) ")
    print("Po stlačení 8888 vypíše všetky ARP dvojice -> bod zo zadania : 4.i) ")


#Prints the files in the prgram
def print_files():
    print()
    print("Dostupne subory na analýzu: ")
    directory = 'traces'
    for filename in os.listdir(directory):
        f = os.path.join(directory,filename)
        if os.path.isfile(f):
            print(f)

    print("")
    print("Súbor : ")



def main():
    print_files()
    file = input()
    with open(file, 'rb') as f:

        pcap = dpkt.pcap.Reader(f)

        LoadAllPackets(pcap,mylist)

        while (True):
            print_menu()
            x = input()
            if (x == "0"):
                exit()

            elif (x == "1"):
                option_1(mylist)

            elif (x == "2"):
                option_2(mylist, "HTTP")

            elif (x == "3"):
                option_2(mylist, "HTTPS")

            elif (x == "4"):
                option_2(mylist, "TELNET")

            elif (x == "5"):
                option_2(mylist, "SSH")

            elif (x == "6"):
                option_2(mylist, "FTP CONTROL")

            elif (x == "7"):
                option_2(mylist, "FTP DATA")

            elif (x == "8"):
                option_2(mylist, "TFTP")

            elif (x == "9"):
                option_3(mylist)






if __name__ == "__main__":
    main()