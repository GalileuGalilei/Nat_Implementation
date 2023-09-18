
from scapy.all import *

nat_table = [] # (IP origem, porta origem, IP destino, porta destino, protocolo de transporte)
nat_ip_to_server = "8.8.254.254"
nat_ip_to_host = "10.1.1.254"
       
def get_port(pkt):
       if pkt.haslayer(TCP):
              return (pkt[TCP].sport, pkt[TCP].dport)
       elif pkt.haslayer(UDP):
              return (pkt[UDP].sport, pkt[UDP].dport)
       else:
              return (0,0)

def change_source(pkt):
       global nat_ip_to_server
       if pkt.haslayer(IP):
              pkt[IP].src = nat_ip_to_server
              #pkt[IP].chksum = None
              #pkt[IP].len = None
              #if pkt.haslayer(TCP):
              #     pkt[TCP].chksum = None
              #elif pkt.haslayer(UDP):
              #    pkt[UDP].chksum = None
              return pkt
       else:
              return 0

def register_on_table(pkt):
       global nat_table
       if pkt.haslayer(IP):
              ip_src = pkt[IP].src
              ip_dst = pkt[IP].dst
              proto = pkt[IP].proto
              sport, dport = get_port(pkt)

              nat_table.append((ip_src, sport, ip_dst, dport, proto))

def get_host(pkt):
       global nat_table
       if pkt.haslayer(IP):
              ip_src = pkt[IP].src
              proto = pkt[IP].proto
              sport, dport = get_port(pkt)

              for entry in nat_table:
                     if entry[1] == dport and entry[2] == ip_src and entry[3] == sport and entry[4] == proto:
                            host = entry[0]
                            nat_table.remove(entry)
                            return host #ip

       return 0

def recalculate_checksum(pkt):
       if pkt.haslayer(IP):
              pkt[IP].chksum = None
              pkt[IP].len = None
              if pkt.haslayer(TCP):
                     pkt[TCP].chksum = None
              elif pkt.haslayer(UDP):
                     pkt[UDP].chksum = None
              return pkt
       else:
              return 0

def log(table):
       file = open("log.txt", "a")
       for entry in table:
              file.write(str(entry))
       file.write(">>>>\n\n")
       file.close()

def handlePacket(pkt):
       global nat_ip_to_server
       global nat_table

       if not pkt.haslayer(IP):
              return

       if pkt[IP].src == nat_ip_to_server:
              return
       
       #escreva a tabela em um arquivo log .txt
       log(nat_table)



       if pkt[IP].dst == nat_ip_to_server:
              host = get_host(pkt) #retorna o ip e remove da tabela
              print("Pacote recebido:")
              print("recebido de: " + pkt[IP].src + " para: " + pkt[IP].dst)
              if host != 0:
                     pkt[IP].dst = host
                     pkt = recalculate_checksum(pkt)
                     pkt[Ether].dst = None
                     print("Pacote alterado:")
                     sendp(pkt, verbose=0, iface='r-eth0')
              else:
                     print("algo de errado nao estah certo, host = 0")
       elif pkt[IP].dst == "8.8.8.8":
              
              register_on_table(pkt)
              pkt = change_source(pkt)
              if pkt != 0:
                     print(pkt.summary())
                     pkt = recalculate_checksum(pkt)
                     pkt[Ether].dst = None
                     sendp(pkt, verbose=0, iface='r-eth1')


       
if __name__ == "__main__":
       
       file = open("log.txt", "w")
       sniff(prn=handlePacket)
       