from scapy.all import sniff,IP,TCP,ICMP
from collections import defaultdict
packet_data=defaultdict(int)
icmp_count=defaultdict(int)
def alert(msg):
    print("!!something is suspious!need to be alert",msg)
def function_calls(packet):
    if packet.haslayer(IP):
        src=packet[IP].src
        packet_data[src]+=1
        if packet_data[src]>5:
            alert("possible scanning from:"+src)
    if packet.haslayer(ICMP):
        src=packet[IP].src
        icmp_count[src]+=1
        if icmp_count[src]>5:
            alert("ICMP flood from:"+src)
        
sniff(prn=function_calls,count=25,store=0)




    
