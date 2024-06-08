#Check if cython code has been compiled
import os
import subprocess
import time
use_extrapolation=False #experimental correlation code
if use_extrapolation:
    print("Importing AfterImage Cython Library")
    if not os.path.isfile("AfterImage.c"): #has not yet been compiled, so try to do so...
        cmd = "python setup.py build_ext --inplace"
        subprocess.call(cmd,shell=True)
#Import dependencies
import netStat as ns
import csv
import numpy as np
import pcapy
import dpkt
import os.path
import platform
import subprocess
import traceback
import socket
import os
import pyshark
import pandas as pd

def is_root():
    return os.geteuid() == 0

#Extracts Kitsune features from given pcap file one packet at a time using "get_next_vector()"
# If wireshark is installed (tshark) it is used to parse (it's faster), otherwise, scapy is used (much slower).
# If wireshark is used then a tsv file (parsed version of the pcap) will be made -which you can use as your input next time
class FE:
    def __init__(self,file_path=None, interface=None,limit=np.inf, type='pcap'):
        assert type in ['pcap', 'tshark', 'csv'], "type should be pcap or tshark or csv"
        if type == 'pcap':
            assert file_path!=None
        elif type == 'tshark':
            assert interface!=None
            assert is_root()
        elif type == 'csv':
            assert file_path!=None
        self.type = type
        self.interface = interface
        self.path = file_path
        self.limit = limit
        self.parse_type = None #unknown
        self.curPacketIndx = 0
        self.tsvin = None #used for parsing TSV file
        self.scapyin = None #used for parsing pcap with scapy

        ### Prep pcap ##
        self.__prep__()

        ### Prep Feature extractor (AfterImage) ###
        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)

    def __prep__(self):
        if self.type == 'pcap':
            if not os.path.isfile(self.path):
                print("File: " + self.path + " does not exist")
                raise Exception()

            # Check file type
            type = self.path.split('.')[-1]

            # If file is pcap
            if type == "pcap" or type == 'pcapng':
                self.parse_type = "pcap"
                print("Reading PCAP file via pcapy...")
                self.scapyin = pcapy.open_offline(self.path)

                # Count the number of packets in the pcap file
                count = 0
                while True:
                    header, _ = self.scapyin.next()
                    if header is None:
                        break
                    count += 1
                
                self.limit = min(self.limit, count)
                self.scapyin = pcapy.open_offline(self.path)
                print("Loaded " + str(self.limit) + " Packets.")
            else:
                print("File: " + self.path + " is not a pcap file")
                raise Exception()
        elif self.type == 'csv':
            self.df = pd.read_csv(self.path)
            self.limit = min(self.limit, len(self.df))
            print("Loaded " + str(self.limit) + " Features.")
        else:
            print("Use Tshark to listen the packet")
            self.tshark = pyshark.LiveCapture(interface='wlo1')
            self.sniff = self.tshark.sniff_continuously()

    def get_next_vector(self):
        if self.curPacketIndx == self.limit:
            print("limit")
            return []

        try:
            if self.type == 'pcap':
                # Parse next packet
                header, data = self.scapyin.next()
                if header is None:
                    return []
                eth = dpkt.ethernet.Ethernet(data)
                # print(eth)
                # Extract Ethernet header information
                src_mac = ':'.join('%02x' % b for b in eth.src)
                dst_mac = ':'.join('%02x' % b for b in eth.dst)
                # print(src_mac, dst_mac)
                eth_type = hex(eth.type)

                # Extract IP information
                src_ip, dst_ip = '', ''
                ip_proto = ''
                src_port, dst_port = '', ''
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    src_ip = '.'.join(map(str, ip.src))
                    dst_ip = '.'.join(map(str, ip.dst))
                    ip_proto = ip.p
                    # print(src_ip, dst_ip, ip_proto)
                # Extract TCP or UDP information
                    
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        src_port = tcp.sport
                        dst_port = tcp.dport
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        src_port = udp.sport
                        dst_port = udp.dport
                    # print(src_port, dst_port)
                if str(src_port) == '': # it's a L2/L1 level protocol
                    # Check for ARP or ICMP as examples of L2/L1 protocols
                    if isinstance(eth.data, dpkt.arp.ARP):
                        arp = eth.data
                        src_ip = socket.inet_ntoa(arp.spa)
                        dst_ip = socket.inet_ntoa(arp.tpa)
                        src_port = 'arp'
                        dst_port = 'arp'
                        ip_proto = 0
                    elif isinstance(eth.data, dpkt.icmp.ICMP):
                        icmp = eth.data
                        src_port = 'icmp'
                        dst_port = 'icmp'
                        ip_proto = 0
                    elif src_ip + str(src_port) + dst_ip + str(dst_port) == '':
                        src_ip = src_mac
                        dst_ip = dst_mac
                # print(header.getts()[0])
                # print(len(data))
                #
                # Update and get stats
                data_dict = {
                    "ip_protocol": str(ip_proto),
                    "source_mac": src_mac,
                    "destination_mac": dst_mac,
                    "source_ip": src_ip,
                    "source_port": str(src_port),
                    "destination_ip": dst_ip,
                    "destination_port": str(dst_port),
                    "data_length": len(data),
                    "timestamp": header.getts()[0]
                }
                return self.nstat.updateGetStats(str(ip_proto), src_mac, dst_mac, src_ip, str(src_port), dst_ip, str(dst_port), len(data), float(header.getts()[0])), data_dict
            elif self.type == 'tshark':
                packet = next(self.sniff, None)
                if packet is None:
                    return []
                # Initialize fields to extract
                src_mac, dst_mac = '', ''
                src_ip, dst_ip = '', ''
                src_port, dst_port = '', ''
                ip_proto = ''
                packet_length = 0
                timestamp = ''

                # Extract MAC addresses
                try:
                    src_mac = packet.eth.src
                    dst_mac = packet.eth.dst
                except AttributeError:
                    pass  # If no Ethernet layer, skip

                # Extract IP layer details
                try:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    ip_proto = packet.ip.proto
                except AttributeError:
                    pass  # If no IP layer, skip

                # Extract TCP/UDP layer details
                if hasattr(packet, 'tcp'):
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                elif hasattr(packet, 'udp'):
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport

                if str(src_port) == '': # it's a L2/L1 level protocol
                    if hasattr(packet, 'arp'):
                        src_ip = packet.arp.src_proto_ipv4
                        dst_ip = packet.arp.dst_proto_ipv4
                        src_port = dst_port = 'arp'
                        ip_proto = 0
                    elif hasattr(packet, 'icmp'):
                        src_port = 'icmp'
                        dst_port = 'icmp'
                        ip_proto = 0
                    elif src_ip + str(src_port) + dst_ip + str(dst_port) == '':
                        src_ip = src_mac
                        dst_ip = dst_mac

                # Get packet length and timestamp
                packet_length = int(packet.length)
                timestamp = packet.sniff_timestamp

                # Update and get stats
                self.curPacketIndx += 1
                data_dict = {
                    "ip_protocol": str(ip_proto),
                    "source_mac": src_mac,
                    "destination_mac": dst_mac,
                    "source_ip": src_ip,
                    "source_port": str(src_port),
                    "destination_ip": dst_ip,
                    "destination_port": str(dst_port),
                    "data_length": packet_length,
                    "timestamp": timestamp
                }

                return self.nstat.updateGetStats(ip_proto, src_mac, dst_mac, src_ip, src_port, dst_ip, dst_port, packet_length, float(timestamp)), data_dict
            elif self.type == 'csv':
                feature = self.df.iloc[self.curPacketIndx]
                self.curPacketIndx+=1
                data_dict = {
                    "ip_protocol": "csv_data",
                    "source_mac": None,
                    "destination_mac": None,
                    "source_ip": None,
                    "source_port": None,
                    "destination_ip": None,
                    "destination_port": None,
                    "data_length": None,
                    "timestamp": time.time(),
                }

                return feature, data_dict
        except Exception as e:
            print(e)
            traceback.print_exc()
            return []


    def pcap2tsv_with_tshark(self):
        print('Parsing with tshark...')
        fields = "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst"
        cmd =  '"' + self._tshark + '" -r '+ self.path +' -T fields '+ fields +' -E header=y -E occurrence=f > '+self.path+".tsv"
        subprocess.call(cmd,shell=True)
        print("tshark parsing complete. File saved as: "+self.path +".tsv")

    def get_num_features(self):
        if self.type == 'csv':
            return len(self.df.iloc[0])
        return len(self.nstat.getNetStatHeaders())
    
    def close(self):
        if self.scapyin:
            self.scapyin.close()
