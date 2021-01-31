from collections import defaultdict
from typing import Dict, Optional, List, IO, Set
import yaml
import os

from .packet import Packet
from .flow import Bin
from .activity import ActivityIntervals


class Device:
    """
    Tracks all Flows that are currently in progress for a single device.
    """

    def __init__(self, name):
        self.bins = defaultdict(Bin)
        self.name = name

    def update(self, packet: Packet, stream: IO, activity: ActivityIntervals):
        self.bins[packet.info()].update(
            packet,
            self.name,
            stream,
            lambda time: activity.active_at_this_time(time, self.name))


class DeviceCollection:
    """
    Holds a collection of devices with their MAC addresses.
    Reads from and writes to a YAML file.
    """

    def __init__(self, yaml_path):
        self.ignored = set()
        self.unclassified: Dict[str, Set[str]] = defaultdict(set)
        self.device_list: List[Device] = []
        self.devices: Dict[str, Device] = dict()
        self.yaml_path = yaml_path
        if os.path.exists(yaml_path):
            with open(yaml_path, 'r') as yaml_file:
                yaml_content = yaml.load(yaml_file)
                if "devices" in yaml_content:
                    for device_name, mac_ids in yaml_content["devices"].items():
                        device = Device(device_name)
                        self.device_list.append(device)
                        for mac_id in mac_ids:
                            self.devices[mac_id] = device
                if "ignore" in yaml_content:
                    for ignored_mac in yaml_content["ignore"]:
                        self.ignored.add(ignored_mac)

    def __getitem__(self, packet: Packet) -> Optional[Device]:
        known_src_device = packet.ethsrc in self.devices
        known_dst_device = packet.ethdst in self.devices

        if known_src_device ^ known_dst_device:  # xor
            if known_src_device:
                device = self.devices[packet.ethsrc]
                packet.src = device.name
                return device
            elif known_dst_device:
                device = self.devices[packet.ethdst]
                packet.dst = device.name
                return device

        if packet.ethsrc not in self.ignored:
            self.unclassified[packet.ethsrc].add(packet.src)
        if packet.ethdst not in self.ignored:
            self.unclassified[packet.ethdst].add(packet.dst)
        return None

    def store(self):
        with open(self.yaml_path, "w") as yaml_file:
            yaml.dump({
                "devices": {
                    device.name: [
                        mac for mac, dev in self.devices.items() if dev == device
                    ]
                    for device in self.device_list
                },
                "ignore": list(self.ignored),
                "unclassified": {
                    mac_addr: list(aliases)
                    for mac_addr, aliases in self.unclassified.items()
                }
            }, yaml_file)

    def flush_bins(self, stream: IO, *, time: int = None, force: bool = False):
        for device in self.device_list:
            remove = []
            for fivetuple, packet_bin in device.bins.items():
                if force or packet_bin.expired(time):
                    packet_bin.flush(stream)
                    remove.append(fivetuple)
            for key in remove:
                device.bins.pop(key)
