#!/usr/bin/env python3

#tshark -t e -Ndmnt -r test.pcap -T fields -e frame.time -e eth.src_resolved -e eth.dst_resolved  -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e tcp.len -e udp.length -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Time '(eth.type == 0x800) or (eth.type == 0x86dd)' > all.tsv

import argparse

DISPLAY_FILTER='!(arp or llc or homeplug-av or (eth.type == 0x8912) or (eth.type == 0x8912))' # 

class Packet:
    def __init__(self, line):
        fields = line.split('\t')
        self.time1 = fields[0]
        self.ethsrc = fields[1]
        self.ethdst = fields[2]
        self.src = fields[3]
        self.dst = fields[4]
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
        return (self.src, self.dst, self.transport, self.srcport, self.dstport)


class Bin:
    def __init__(self):
        self.time = 0
        self.time1 = ''
        self.count = 0
        self.size = 0
        self.protos = set()

    def info(self):
        return (self.time1, str(self.count), str(self.size), str(self.protos))
    
    def update(self, p):
        ret = None
        if self.time == 0:
            self.time = p.time
            self.time1 = p.time1
        elif p.time - self.time < threshold:
            ret = self.info()
            self.time = p.time
            self.time1 = p.time1
            self.count = 0
            self.size = 0
            self.protos = set()
        self.count += 1
        self.size += p.size
        self.protos.add(p.proto)
        return ret

class Stat:
    def __init__(self):
        self.bins = {}

    def update(self, p):        
        k = p.info()
        
        bin = self.bins.get(k)
        if not bin:
            self.bins.update({k: Bin()})
        x = self.bins[k].update(p)
        if x:
            return k + x

threshold = 1000000

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", help="file of packets")
    parser.add_argument("destination", help="file to append to")
    parser.add_argument("-t", "--threshold", type=int, help="maximum bin timespan in microseconds")
    parser.add_argument("-i", "--ignored", help="comma separated list of mac addresses which should be completely ignored (e.g. the raspberry pi, because it was a routed access point")
    parser.add_argument("-r", "--routers", help="comma separated list of mac addresses of routers which should be ignored for per device analysis")
    args = parser.parse_args()

    in_file = open(args.source, 'r') # , newline=''
    out_file = open(args.destination, 'a')

    if args.threshold:
        threshold = args.threshold

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

    def get_device(p):
        macs = set()

        put(macs, p.ethsrc)
        put(macs, p.ethdst)

        if (not macs) or (len(macs) > 1):
            print("local traffic")
            return None
        return macs.pop()

    stats = {}

    def update_stats(p):
        device = get_device(p)
        if not device:
            return
        
        stat = stats.get(device)
        if not stat:
            stats.update({device: Stat()})
        return stats[device].update(p)
    
    last = 0

    line = in_file.readline()
    while line:
        p = Packet(line)
        x = update_stats(p)
        if x:
            out_file.write('\t'.join((device,) + x) + '\n')
        else:
            if p.time - threshold > last:
                for device, stat in stats.items():
                    removals = set()
                    for fivetuple, bin in stat.bins.items():
                        if bin.time - threshold > last:
                            out_file.write('\t'.join((device,) + fivetuple + bin.info()) + '\n')
                            removals.add(fivetuple)
                    for r in removals:
                        stat.bins.pop(r)
                last = p.time
        line = in_file.readline()

    for device, stat in stats.items():
        print(device)
        for fivetuple, bin in stat.bins.items():
                out_file.write('\t'.join((device,) + fivetuple + bin.info()) + '\n')

    in_file.close()
    out_file.close()