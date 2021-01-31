
class Packet:
    """
    Representation of a single packet as parsed from a tshark TSV export line.
    """

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
        return self.src, self.dst, self.transport, self.srcport, self.dstport
