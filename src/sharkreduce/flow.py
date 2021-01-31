from typing import IO, Callable, Set
import socket

from .packet import Packet

# Maximum time duration covered by a single bin in Microseconds
MAX_BIN_AGE = 1_000_000


class Bin:
    """
    Accumulates information for multiple packets within a time interval.
    """

    @staticmethod
    def print_headers(stream: IO):
        stream.write("\t".join((
            "device",
            "microseconds",
            "timestamp",
            "packets",
            "bytes",
            "src",
            "dst",
            "transport",
            "srcport",
            "dstport",
            "proto",
            "dnsaddr",
            "active_use"
        )) + "\n")

    @staticmethod
    def from_row(row: str) -> 'Bin':
        cols = row.split("\t")
        res = Bin()
        res.device_name = cols[0]
        res.microsecs = int(cols[1])
        res.time = cols[2]
        res.count = int(cols[3])
        res.size = int(cols[4])
        res.fivetuple = (cols[5], cols[6], cols[7], cols[8], cols[9])
        res.protocols = {cols[10]}
        res.active = bool(int(cols[12]))
        return res

    def __init__(self):
        self.microsecs = 0
        self.time = ''
        self.count = 0
        self.size = 0
        self.protocols: Set[str] = set()
        self.fivetuple = tuple()
        self.device_name = ''
        self.active = False

    def info(self):
        return (
            self.device_name,
            str(self.microsecs),
            self.time,
            str(self.count),
            str(self.size),
            *self.fivetuple,
            self.protocol(),
            "TODO",
            str(int(self.active)))

    def update(self, packet: Packet, device_name: str, stream: IO, activity_fn: Callable[[int], bool]):
        ret = None
        if self.microsecs == 0:
            # Initial packet
            self.microsecs = packet.time
            self.time = packet.time1
            self.fivetuple = packet.info()
            self.device_name = device_name
            self.active = activity_fn(self.microsecs)
        elif packet.time - self.microsecs > MAX_BIN_AGE:
            # New packet which is so far in the future that
            # the bin is finished and resets.
            self.flush(stream)
            self.microsecs = packet.time
            self.time = packet.time1
        self.count += 1
        self.size += packet.size
        self.protocols.add(packet.proto)
        return ret

    def flush(self, stream) -> bool:
        if self.count:
            stream.write('\t'.join(self.info()) + '\n')
            self.count = 0
            self.size = 0
            self.protocols = set()
            return True
        else:
            return False

    def expired(self, time: int) -> bool:
        return self.count > 0 and time - self.microsecs > MAX_BIN_AGE

    def protocol(self):
        for protocol in self.protocols:
            if protocol != "TCP" and protocol != "UDP" and not protocol.startswith("TLS"):
                return protocol
        try:
            # Try to convert destination port to service name.
            return socket.getservbyport(int(self.fivetuple[4]), self.fivetuple[2].lower()).upper()
        except OSError:
            try:
                # Try to convert source port to service name.
                return socket.getservbyport(int(self.fivetuple[3]), self.fivetuple[2].lower()).upper()
            except OSError:
                return "N/A"
