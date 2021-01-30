#!/usr/bin/env python3

# tshark -t e -Ndmnt -r test.pcap -T fields -e frame.time -e eth.src_resolved -e eth.dst_resolved  -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e tcp.len -e udp.length -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Time '(eth.type == 0x800) or (eth.type == 0x86dd)' > all.tsv

import argparse
from collections import defaultdict

# Are these microseconds or milliseconds?
MAX_BIN_AGE = 1_000_000


class Packet:
    def __init__(self, line):
        fields = line.split('\t')
        self.time1 = fields[0]
        self.ethsrc = fields[1]
        self.ethdst = fields[2]
        self.src = fields[3]
        self.dst = fields[4]
        # TODO: Determine protocol by looking at destination port.
        self.proto = fields[5]
        self.tcplen = fields[6]
        self.udplen = fields[7]
        self.tcpsrc = fields[8]
        self.tcpdst = fields[9]
        self.udpsrc = fields[10]
        self.udpdst = fields[11]
        self.time2 = fields[12]

        self.size = int('0' + self.tcplen + self.udplen)
        self.srcport = self.tcpsrc + self.udpsrc
        self.dstport = self.tcpdst + self.udpdst
        if self.tcplen != '':
            self.transport = 'TCP'
        elif self.udplen != '':
            self.transport = 'UDP'
        else:
            self.transport = 'other'
        self.time = int(self.time2.split('.')[0] + self.time2.split('.')[1])

    def info(self):
        return self.src, self.dst, self.transport, self.srcport, self.dstport


class Bin:
    def __init__(self):
        self.time = 0
        self.time1 = ''
        self.count = 0
        self.size = 0
        self.protos = set()

    def info(self):
        return self.time1, str(self.count), str(self.size), str(self.protos)
    
    def update(self, packet):
        ret = None
        if self.time == 0:
            # Initial packet
            self.time = packet.time
            self.time1 = packet.time1
        # JB: If flipped the operator here from < to >.
        elif packet.time - self.time > MAX_BIN_AGE:
            # New packet which is so far in the future that
            # the bin is finished and resets.
            ret = self.info()
            self.time = packet.time
            self.time1 = packet.time1
            self.count = 0
            self.size = 0
            self.protos = set()
        self.count += 1
        self.size += packet.size
        self.protos.add(packet.proto)
        return ret


class Stat:
    def __init__(self):
        self.bins = defaultdict(Bin)

    def update(self, packet):
        packet_fivetuple = packet.info()
        finished_bin_info = self.bins[packet_fivetuple].update(packet)
        if finished_bin_info:
            return packet_fivetuple + finished_bin_info


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", help="file of packets")
    parser.add_argument("destination", help="file to append to")
    parser.add_argument("-t", "--threshold", type=int, help="maximum bin timespan in microseconds")
    parser.add_argument("-i", "--ignored", help="comma separated list of mac addresses which should be completely ignored (e.g. the raspberry pi, because it was a routed access point")
    parser.add_argument("-r", "--routers", help="comma separated list of mac addresses of routers which should be ignored for per device analysis")
    args = parser.parse_args()

    in_file = open(args.source, 'r')  # , newline=''
    out_file = open(args.destination, 'a')

    if args.threshold:
        MAX_BIN_AGE = args.threshold

    ignored = set()
    if args.ignored:
        for i in args.ignored.split(','):
            ignored.add(i)
        
    routers = set()
    if args.routers:
        for r in args.routers.split(','):
            routers.add(r)

    def put(macs, mac):
        if (not (mac in ignored)) and (not (mac in routers)):
            macs.add(mac)

    def get_device(of_packet):
        macs = set()

        put(macs, of_packet.ethsrc)
        put(macs, of_packet.ethdst)

        if (not macs) or (len(macs) > 1):
            print("local traffic")
            return None
        return macs.pop()

    stats = defaultdict(Stat)

    def update_stats(of_packet):
        device_for_packet = get_device(of_packet)
        if not device_for_packet:
            return
        return stats[device_for_packet].update(of_packet)
    
    last = 0

    line = in_file.readline()
    while line:
        p = Packet(line)
        finished_bin = update_stats(p)
        if finished_bin:
            packet_device = get_device(p)
            out_file.write('\t'.join((packet_device,) + finished_bin) + '\n')
        else:
            # Print and remove bins that have become very old.
            if p.time - MAX_BIN_AGE > last:
                for device, stat in stats.items():
                    removals = set()
                    for fivetuple, packet_bin in stat.bins.items():
                        if packet_bin.time - MAX_BIN_AGE > last:
                            out_file.write('\t'.join((device,) + fivetuple + packet_bin.info()) + '\n')
                            removals.add(fivetuple)
                    for r in removals:
                        stat.bins.pop(r)
                last = p.time
        line = in_file.readline()

    for device, stat in stats.items():
        print(device)
        for fivetuple, packet_bin in stat.bins.items():
            out_file.write('\t'.join((device,) + fivetuple + packet_bin.info()) + '\n')

    in_file.close()
    out_file.close()
