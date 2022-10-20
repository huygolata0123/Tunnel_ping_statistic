import argparse
import os
import sys
import time
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP
import pickle
from enum import Enum
import pandas as pd
import matplotlib
import matplotlib.pyplot as plt
import binascii
def analyze_pickle(pickle_file_in):

    packets_for_analysis = []
    
    with open(pickle_file_in, 'rb') as pickle_fd:
        client_ip = pickle.load(pickle_fd)
        server_ip = pickle.load(pickle_fd)
        packets_for_analysis = pickle.load(pickle_fd)

    # Plot the receive window size on the client side.
    client_pkts = []
    for pkt_data in packets_for_analysis:
        if pkt_data['direction'] == PktDirection.server_to_client:
            continue
        client_pkts.append({'Time': pkt_data['relative_timestamp'],
            'Size': pkt_data['size'],'BaseLine': 36})

    df = pd.DataFrame(data=client_pkts)
    fig, ax1 = plt.subplots()
    df.plot(x='Time', y='Size', color='r', ax=ax1)
    df.plot(x='Time', y='BaseLine', color='b', ax=ax1)
    ax1.tick_params('y', colors='r')
    ax1.tick_params('y', colors='b')
    plt.show()
    plt.close()

class PktDirection(Enum):
    not_defined = 0
    client_to_server = 1
    server_to_client = 2

def printable_timestamp(ts, resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    return '{}.{}'.format(ts_sec_str, ts_subsec)

def pickle_pcap(pcap_file_in, pickle_file_out):
    print('Opening {}...'.format(file_name))
    client_ip = '192.168.16.128'
    server_ip = '192.168.16.130'
    count = 0
    interesting_packet_count = 0
    packets_for_analysis = []
    ip_pkt = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1
        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            continue
        if ether_pkt.type != 0x0800:
            continue
        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 1:
            continue
        if (ip_pkt.src != server_ip) and (ip_pkt.src != client_ip):
            continue
        if (ip_pkt.dst != server_ip) and (ip_pkt.dst != client_ip):
            continue
        if ip_pkt.src == client_ip:
            if ip_pkt.dst != server_ip:
                continue
            direction = PktDirection.client_to_server
        elif ip_pkt.src == server_ip:
            if ip_pkt.dst != client_ip:
                continue
            direction = PktDirection.server_to_client
        else:
            continue
        interesting_packet_count += 1
        if interesting_packet_count == 1:
            first_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
            first_pkt_timestamp_resolution = pkt_metadata.tsresol
            first_pkt_ordinal = count
            icmp_pkt = ether_pkt[ICMP]
            icmp_length = ip_pkt.len - 20
            print("Type ICMP: " + str(icmp_pkt.type))
            print("Code ICMP: " + str(icmp_pkt.code))
            print("Packet[1]-->Length: "+ str(icmp_length)) 
            pkt = binascii.hexlify(bytes(icmp_pkt[1]))
            str_pkt= str(pkt,'ascii')
            print("-"*50)
            print("ANALYSIS PTUNNEL PROTOCOL")
            print("-"*50)
            print("Magic Number (4 bytes): "+ str(pkt[0:8]))
            print("IP Address Destination (4 bytes): "+ str(pkt[8:16]))
            print("Port Destination (4 bytes): "+str(pkt[16:24]))
            print("State - kUser/kProxy (1<<30 cho Client) (4 bytes): "+str(pkt[24:32]))
            print("Ack Number (4 bytes): "+ str(pkt[32:40]))
            print("Length of Data (4 bytes): "+str(pkt[40:48]))
            print("Sequence Number (2 bytes): "+str(pkt[48:52]))
            print("Indentifier (2 bytes): "+str(pkt[52:56]))
        last_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        last_pkt_timestamp_resolution = pkt_metadata.tsresol
        last_pkt_ordinal = count
        this_pkt_relative_timestamp = last_pkt_timestamp - first_pkt_timestamp
        icmp_payload_len = ip_pkt.len-20;
        
        icmp_type = icmp_pkt.type
        icmp_code = icmp_pkt.code

        fmt = '{ts:>10.6f}s len={len:<6d}'
        if direction == PktDirection.client_to_server:
            fmt = '{arrow}' + fmt
            arr = '-->'
        else:
            fmt = '{arrow:>69}' + fmt
            arr = '<--'

        print(fmt.format(arrow = arr, ts = this_pkt_relative_timestamp / pkt_metadata.tsresol ,len = icmp_payload_len))
        #Khai bao data
        pkt_data = {}
        pkt_data['direction'] = direction
        pkt_data['size']= icmp_payload_len;
        pkt_data['relative_timestamp'] = this_pkt_relative_timestamp / \
                                         pkt_metadata.tsresol
        packets_for_analysis.append(pkt_data)

    print('{} contains {} packets ({} interesting)'.
            format(file_name, count, interesting_packet_count))
    print('First packet in connection: Packet #{} {}'.
          format(first_pkt_ordinal,
                 printable_timestamp(first_pkt_timestamp,
                                     first_pkt_timestamp_resolution)))
    print('Last packet in connection: Packet #{} {}'.
          format(last_pkt_ordinal,
                 printable_timestamp(last_pkt_timestamp,
                                     last_pkt_timestamp_resolution)))
    print('Writing pickle file {}...'.format(pickle_file_out), end='')
    with open(pickle_file_out, 'wb') as pickle_fd:
        pickle.dump(client_ip, pickle_fd)
        pickle.dump(server_ip, pickle_fd)
        pickle.dump(packets_for_analysis, pickle_fd)
    print('done.')
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    parser.add_argument('--out',metavar='<file_out>',required=True)
    args = parser.parse_args() 
    file_name = args.pcap
    other_file = args.out
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)
    pickle_pcap(file_name,other_file)
    analyze_pickle(other_file)
    sys.exit(0)

