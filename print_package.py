
from scapy.all import *

#escreva uma função para verificar se o checksum esta correto
def checksum(pkt):
        if pkt.haslayer(IP):
                print("IP checksum: " + str(pkt[IP].chksum))
                print("IP len: " + str(pkt[IP].len))
                if pkt.haslayer(TCP):
                        print("TCP checksum: " + str(pkt[TCP].chksum))
                elif pkt.haslayer(UDP):
                        print("UDP checksum: " + str(pkt[UDP].chksum))
                else:
                        print("No checksum")
        else:
                print("No checksum")


def handlePacket(pkt):
        if(pkt.haslayer(IP)):
               print("recebido de: " + pkt[IP].src + " para: " + pkt[IP].dst)
if __name__ == "__main__":
        sniff(prn=handlePacket)

