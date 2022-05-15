#!/usr/bin/env python3
import csv
import sys
import os
from binascii import hexlify
from scapy.all import *
pcap_file = sys.argv[1]

if __name__ == '__main__':

    try:
        pcap = PcapReader(pcap_file)
    except Exception as e:
        print(f'Error! {e}')
        sys.exit(1)

    dir_name = os.path.dirname(pcap_file)
    base_name = os.path.basename(pcap_file)
    output_tcp = csv.writer(open(dir_name + '/output_tcp_' + base_name.replace(".pcap","") + '.csv', 'w'), delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    output_udp = csv.writer(open(dir_name + '/output_udp_' + base_name.replace(".pcap","") + '.csv', 'w'), delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    output_icmp = csv.writer(open(dir_name + '/output_icmp_' + base_name.replace(".pcap","") + '.csv', 'w'), delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    ip_header = ['time', 'ip_version', 'ip_ihl', 'ip_tos', 'ip_len', 'ip_id', 'ip_flags', 'ip_frag', 'ip_ttl', 'ip_proto', 'ip_chksum', 'ip_src', 'ip_dst', 'ip_options']

    ip_tcp_header = (ip_header + ['tcp_sport', 'tcp_dport', 'tcp_seq', 'tcp_ack', 'tcp_dataofs', 'tcp_reserved', 'tcp_flags', 'tcp_window', 'tcp_chksum', 'tcp_urgptr', 'tcp_options', 'payload'])
    output_tcp.writerow(ip_tcp_header)

    ip_udp_header = (ip_header + ['udp_sport', 'udp_dport', 'udp_len', 'udp_chksum', 'payload'])
    output_udp.writerow(ip_udp_header)

    ip_icmp_header = (ip_header + ['icmp_type', 'icmp_code', 'icmp_chksum', 'icmp_id', 'icmp_seq', 'icmp_ts_ori', 'icmp_ts_rx', 'icmp_gw', 'icmp_ptr', 'icmp_reserved', 'icmp_length', 'icmp_addr_mask', 'icmp_nexthopmtu', 'icmp_unused', 'payload'])
    output_icmp.writerow(ip_icmp_header)


    for packet in pcap:
        if packet.haslayer(IP):

            row = []
            row.append(packet.time)
            row.append(packet['IP'].version)
            row.append(packet['IP'].ihl)
            row.append(packet['IP'].tos)
            row.append(packet['IP'].len)
            row.append(packet['IP'].id)
            row.append(packet['IP'].flags)
            row.append(packet['IP'].frag)
            row.append(packet['IP'].ttl)
            row.append(packet['IP'].proto)
            row.append(packet['IP'].chksum)
            row.append(packet['IP'].src)
            row.append(packet['IP'].dst)
#                row.append('|'.join(packet['IP'].options))
            row.append(packet['IP'].options)

            if packet.haslayer(TCP):
                row.append(packet['TCP'].sport)
                row.append(packet['TCP'].dport)
                row.append(packet['TCP'].seq)
                row.append(packet['TCP'].ack)
                row.append(packet['TCP'].dataofs)
                row.append(packet['TCP'].reserved)
                row.append(packet['TCP'].flags)
                row.append(packet['TCP'].window)
                row.append(packet['TCP'].chksum)
                row.append(packet['TCP'].urgptr)
                row.append(packet['TCP'].options)
                row.append(hexlify(bytes(packet['TCP'].payload)).decode())
                output_tcp.writerow(row)

            if packet.haslayer(UDP):	
                row.append(packet['UDP'].sport)
                row.append(packet['UDP'].dport)
                row.append(packet['UDP'].len)
                row.append(packet['UDP'].chksum)
                row.append(hexlify(bytes(packet['UDP'].payload)).decode())
                output_udp.writerow(row)

            if packet.haslayer(ICMP):
                row.append(packet['ICMP'].type)
                row.append(packet['ICMP'].code)
                row.append(packet['ICMP'].chksum)
                row.append(packet['ICMP'].id)
                row.append(packet['ICMP'].seq)
                row.append(packet['ICMP'].ts_ori)
                row.append(packet['ICMP'].ts_rx)
                row.append(packet['ICMP'].gw)
                row.append(packet['ICMP'].ptr)
                row.append(packet['ICMP'].reserved)
                row.append(packet['ICMP'].length)
                row.append(packet['ICMP'].addr_mask)
                row.append(packet['ICMP'].nexthopmtu)
                row.append(packet['ICMP'].unused)
                row.append(hexlify(bytes(packet['ICMP'].payload)).decode())
                output_icmp.writerow(row)