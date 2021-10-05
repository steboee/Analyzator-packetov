import binascii

import dpkt



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
    def __init__(self,position,length_real,length_media):
        self.position = position
        self.length_real = length_real
        self.length_media = length_media


    class Protokol:
        def __init__(self,protokol):
            self.protokol = protokol
        def vypis(self):
            print("Protokol : " + str(self.protokol))

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



def length_of_packet_media(length):
    x = 0
    if (length < 60) :
        x = 64
    else:
        x = length +4
    return x

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


def type_of_packet(whole_packet):
    a = whole_packet[12]
    b = whole_packet[13]
    c = a + b
    sum = int(c,16)
    if sum >= 1536:
        type = "Ethernet II"
        #print(type)
    else:
        a = whole_packet[14]
        b = whole_packet[15]
        c = a + b
        #print(c)
        if (c == "ffff"):
            type = "IEEE 802.3 Novell RAW"
        else:
            if(c == "aaaa"):
                type = "IEEE 802.3 LLC + SNAP"
            else:
                type = "IEEE 802.3 LLC"

    return type

def protocol_checker(packet,whole_packet):
    protokol_number = ""
    file = open('protocols', 'r')

    if (packet.TYPE.typ == "Ethernet II"):
        protokol_number = "0x" + whole_packet[12] + whole_packet[13]

    """
    elif (packet.TYPE.typ == "IEEE 802.3 LLC + SNAP"):
        protokol_number = "0x" + whole_packet[20] + whole_packet[21]

    elif (packet.TYPE.typ == "IEEE 802.3 Novell RAW"):
        protokol_number = whole_packet[19]

    elif (packet.TYPE.typ == "IEEE 802.3 LLC"):
        pass
    """



    for riadok in file:
        a =  riadok.split('=')
        if (protokol_number == a[0].strip()):
            return a[1].strip()

    file.close()
    return protokol_number


def LoadAllPackets(pcap):
    position = 1
    for packet in pcap:
        media_length = length_of_packet_media(len(packet[1]))
        smallpacket = PACKET(position,len(packet[1]),media_length)
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

                text = text + (l +  " |   " + riadok) + "\n"
                pc = pc +1
                riadok = "".join("{:02x}".format(x)) + " "

            counter = counter + 1
            a = "".join("{:02x}".format(x))
            whole_packet.append(a)


        text = text + (l + " |   " + riadok)+"\n"
        smallpacket.VYPIS_PACKETU = smallpacket.VYPIS_PACKETU(text)
        mylist.append(smallpacket)

        src = source_mac_adress(whole_packet)
        dst = dest_mac_adress(whole_packet)
        type = type_of_packet(whole_packet)
        smallpacket.TYPE = smallpacket.TYPE(type)




        smallpacket.Destination_mac_ad = smallpacket.Destination_mac_ad(dst)
        smallpacket.Source_mac_ad = smallpacket.Source_mac_ad(src)

        smallpacket.Protokol = smallpacket.Protokol(protocol_checker(smallpacket,whole_packet))

        position = position + 1






def print_packets(list):
    num_of_packets = list.__len__()

    print("----------------------PRINTING PACKETS-----------------------------\n\n")
    for i in range(num_of_packets-1):
        print("--------------------------------PACKET_" + str(list[i].position) + "----------------------------------\n")

        print(list[i].VYPIS_PACKETU.text)
        print("Dĺžka packetu : " + str(list[i].length_real))
        print("Dĺžka packetu po médiu : " + str(list[i].length_media))
        print(list[i].TYPE.typ + "\n")
        print("DESTINATION MAC ADDRESS: "+ list[i].Destination_mac_ad.adresa)
        print("SOURCE MAC ADDRESS: " + list[i].Source_mac_ad.adresa + "\n")
        print(list[i].Protokol.protokol + "\n")
        print("\n----------------------------END OF PACKET "+ str(list[i].position) +"-------------------------------\n\n")







def print_menu():
    print("--------------------")
    print("Analyzátor packetov")
    print("--------------------\n")
    print("Po stlačení 1 vypíšeš všetky packety a info ")



def main():

    with open('trace-26.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_menu()

        LoadAllPackets(pcap)
        print_packets(mylist)


main()

