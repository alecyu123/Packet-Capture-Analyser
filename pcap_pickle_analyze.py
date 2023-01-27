import argparse
import os
import sys
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import time
from enum import Enum
import pickle

class PktDirection(Enum):
    not_defined = 0
    client_to_server = 1
    server_to_client = 2

def printable_timestamp(ts, resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
    return '{}.{}'.format(ts_sec_str, ts_subsec)

def analyze_pickle(pickle_file_in):

    packets_for_analysis = []
    
    with open(pickle_file_in, 'rb') as pickle_fd:
        client_ip_addr_port = pickle.load(pickle_fd)
        server_ip_addr_port = pickle.load(pickle_fd)
        packets_for_analysis = pickle.load(pickle_fd)

    # Print a header
    print('##################################################################')
    print('TCP session between client {} and server {}'.
          format(client_ip_addr_port, server_ip_addr_port))
    print('##################################################################')
        
    # Print format string
    fmt = ('[{ordnl:>5}]{ts:>10.6f}s {flag:<3s} seq={seq:<8d} '
           'ack={ack:<8d} len={len:<6d} win={win:<9d}')

    for pkt_data in packets_for_analysis:

        direction = pkt_data['direction']

        if direction == PktDirection.client_to_server:
            print('{}'.format('-->'), end='')
        else:
            print('{:>60}'.format('<--'), end='')

        print(fmt.format(ordnl = pkt_data['ordinal'],
                         ts = pkt_data['relative_timestamp'],
                         flag = pkt_data['tcp_flags'],
                         seq = pkt_data['seqno'],
                         ack = pkt_data['ackno'],
                         len = pkt_data['tcp_payload_len'],
                         win = pkt_data['window']))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pickle_in', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    print(args)
    pickle_file = args.pickle_in

    if not os.path.isfile(pickle_file):
        print('"{}" does not exist'.format(pickle_file), file=sys.stderr)
        sys.exit(-1)

    analyze_pickle(pickle_file)
    sys.exit(0)