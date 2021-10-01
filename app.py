import binascii
import struct

from libpcap import pcap
from scapy.all import PcapReader
from scapy.utils import rdpcap





def dest_mac_adress(list_of_packet_bytes):
    destin = ""
    i = 0
    while (i != 8):
        destin = destin + str(list_of_packet_bytes[i])
        i = i + 1

    return destin



def source_mac_adress(list_of_packet_bytes):
    source = ""
    i = 8
    while (i != 16):
        source = source + str(list_of_packet_bytes[i])
        i = i + 1

    return source


packets = PcapReader("trace-20.pcap")
counter = 1

for packet in packets:
    pc = rdpcap("trace-20.pcap")
    print(pc.res[1].fields)
    break
    a = packets.read_packet()

    print(a)
    packet = binascii.hexlify(bytes(packet))

    print(packet)
    break
    whole_packet = []

    pkt = binascii.hexlify(bytes(packet))
    print(pkt)
    print(len(packet))
    count = -2

    for a in pkt:
        if (count >= 0):
            whole_packet.append(chr(a))
        count = count + 1

    src = source_mac_adress(whole_packet)
    dst = dest_mac_adress(whole_packet)
    print("destination mac adress : " + str(dst))
    print("source mac adress : " + str(src))
    break

"""
        if (count == -1 or count == 0):
            count = count + 1
            continue

        if (count % 2 == 0):
            dest_mac = dest_mac + a
            if (count !=12):
                dest_mac = dest_mac + ":"
        else:
            dest_mac = dest_mac + a
        if (count == 12):
            source_mac = source_mac +a

"""

"""
with open('trace-20.pcap', 'rb') as fobj:
    raw_bytes = fobj.read()
    print(' '.join(map(lambda x: '{:08b}'.format(x), raw_bytes)))

    print(str(counter) + " " + str(packet))
    print("\n\n")
    counter = counter + 1

    codecs.decode()

    print(str(counter) + " " + str(packet) + "\n")
"""

"""
    print("PACKET: "+ str(counter))
    print("\n\n" + pkt + "\n \n")
    print("Destination mac adress : " + dest_mac + "\n")

"""
