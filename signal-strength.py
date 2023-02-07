from scapy.all import *
import sys

mac = sys.argv[2]

def signal_strength(packet): 
    if packet.haslayer(Dot11): # 해당 패킷에 어떤 protocol layer이 있는지 확인하는 함수
        if packet.addr2 == mac:
            print("signal strength: ", packet.dBm_AntSignal)

def main(net):
    sniff(iface=net, prn=signal_strength)

if __name__=="__main__":
    main(sys.argv[1])
