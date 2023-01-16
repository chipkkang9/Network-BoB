from scapy.all import *
import sys
import secrets

def get_BSSID():
    addr1 = str(secrets.token_hex(1))
    addr2 = str(secrets.token_hex(1))
    addr3 = str(secrets.token_hex(1))
    addr4 = str(secrets.token_hex(1))
    addr5 = str(secrets.token_hex(1))
    addr6 = str(secrets.token_hex(1))

    addr=addr1+':'+addr2+':'+addr3+':'+addr4+':'+addr5+':'+addr6

    return addr

def main(net, file):
    file_number = 0

    tot = get_BSSID()
    manc = get_BSSID()
    manu = get_BSSID()
    dogh = get_BSSID()
    newu = get_BSSID()
    liv = get_BSSID()
    ful = get_BSSID()
    bha = get_BSSID()
    brent = get_BSSID()
    chel = get_BSSID()

    while True:
        if file_number > 9 :
            file_number -= 10

        f = open(file)
        SSIDs = f.readlines()[file_number]
        netSSID = SSIDs.encode('UTF-8')
        iface = net

        if file_number == 0:
            addresses = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=tot, addr3=tot)
        if file_number == 1:
            addresses = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=manc, addr3=manc)
        if file_number == 2:
            addresses = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=manu, addr3=manu)
        if file_number == 3:
            addresses = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=dogh, addr3=dogh)
        if file_number == 4:
            addresses = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=newu, addr3=newu)
        if file_number == 5:
            addresses = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=liv, addr3=liv)
        if file_number == 6:
            addresses = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=ful, addr3=ful)
        if file_number == 7:
            addresses = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=bha, addr3=bha)
        if file_number == 8:
            addresses = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=brent, addr3=brent)
        if file_number == 9:
            addresses = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=chel, addr3=chel)



        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))
        rsn = Dot11EltRSN()
        frame = RadioTap()/addresses/beacon/essid/rsn

        #hexdump(frame)
        sendp(frame, iface=iface, inter=0.100)
        file_number += 1
        f.close()

if __name__=='__main__':
    main(sys.argv[1], sys.argv[2])

