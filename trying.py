import binascii

import dpkt
import datetime
from dpkt.utils import mac_to_str, inet_to_str
from scapy.utils import rdpcap


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
            raise ValueError('Ghosts allowed only');


mylist = PACKETList()

class PACKET:
    def __init__(self,position):
        self.position = position

    class TYPE:
        def __init__(self,typ):
            self.typ = typ

        def vypis(self):
            print("TYPE : " + str(self.typ))



    class Destination_mac_ad:
        def __init__(self, adresa):
            self.adresa = adresa

        def vypis(self):
            print("Destination address: " + str(self.adresa))



    class Source_mac_ad:
        def __init__(self, adresa):
            self.adresa = adresa

        def vypis(self):
            print("Source address: " + str(self.adresa))

    class VYPIS_PACKETU:
        def __init__(self, text):
            self.text = text

        def vypis(self):
            print(self.text)




def dest_mac_adress(list_of_packet_bytes):
    destin = ""
    i = 0
    while (i != 5):
        destin = destin + str(list_of_packet_bytes[i])+":"
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









def ether(list_of_packet_bytes):
    type = ""
    i = 12
    while (i != 13):
        type = type + str(list_of_packet_bytes[i])
        i = i + 1
    type = type + str(list_of_packet_bytes[i])



def LoadAllPackets(pcap):

    position = 1
    for packet in pcap:
        smallpacket = PACKET(position)
        other = packet[1]
        pc = 0
        l = ""
        riadok = ""
        counter = 0
        whole_packet = []
        global text
        text = ""
        for x  in other:
            if (counter == 0):
                riadok = "" .join("{:02x}".format(x))+" "

            elif (counter <16):
                riadok = riadok + "".join("{:02x}".format(x)) + " "

            else:
                counter = 0
                l = str(hex(pc).lstrip("0x").rstrip("L"))
                l = l.zfill(3)
                l = l + "0"
                #print(l +  " |   " + riadok)

                text = text + (l +  " |   " + riadok) + "\n"
                pc = pc +1

                riadok = "".join("{:02x}".format(x)) + " "











            counter = counter + 1
            a = "".join("{:02x}".format(x))
            whole_packet.append(a)
        #print(l + " |   " + riadok)
        text = text + (l + " |   " + riadok)+"\n"
        smallpacket.VYPIS_PACKETU = smallpacket.VYPIS_PACKETU(text)
        mylist.append(smallpacket)


        src = source_mac_adress(whole_packet)
        dst = dest_mac_adress(whole_packet)

        smallpacket.Destination_mac_ad = smallpacket.Destination_mac_ad(dst)
        smallpacket.Source_mac_ad = smallpacket.Source_mac_ad(src)
        #print("\n")
        #print("destination mac adress : " + str(dst))
        #print("source mac adress : " + str(src))
        #print("Lenght of packet : " + str(len(packet[1])) + " Bytes")
        #print(ether(whole_packet))


        #print("\n----------------------------END OF PACKET-------------------------------\n\n")
        position = position + 1

def print_packets(list):
    num_of_packets = list.__len__()

    print("----------------------PRINTING PACKETS-----------------------------\n\n")
    for i in range(num_of_packets-1):
        print("----------------------------PACKET_" + str(list[i].position) + "------------s-------------------\n")
        print(list[i].VYPIS_PACKETU.vypis())
        print("\n----------------------------END OF PACKET-------------------------------\n\n")




def print_menu():
    print("--------------------")
    print("Analyzátor packetov")
    print("--------------------\n")
    print("Po stlačení 1 vypíšeš všetky packety a info ")



def main():

    with open('trace-20.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_menu()


        LoadAllPackets(pcap)

        print_packets(mylist)
        print("HELLO")


main()

