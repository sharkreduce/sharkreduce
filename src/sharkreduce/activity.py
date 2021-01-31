import yaml
import os
from typing import Dict, List, Set, Optional
from collections import defaultdict

from . import flow
from .flow import Bin


class ActivityInterval:

    @staticmethod
    def from_dict(interval_dict):
        res = ActivityInterval()
        res.from_time, res.from_microsecs = interval_dict["_from"]
        res.to_time, res.to_microsecs = interval_dict["_to"]
        for device_name, device_info in interval_dict["devices"].items():
            res.active_per_device[device_name] = device_info["active"]
            for dest in device_info["destinations"]:
                res.bytes_per_destination_per_device[device_name][dest["dest"]] = dest["size"]
        return res

    def __init__(self):
        self.from_microsecs = 0
        self.to_microsecs = 0
        self.from_time = 0
        self.to_time = 0
        self.bytes_per_destination_per_device: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.active_per_device: Dict[str, bool] = defaultdict(bool)

    def update(self, with_bin: Bin):
        if self.from_microsecs == 0:
            self.from_microsecs = with_bin.microsecs
            self.from_time = with_bin.time
        if with_bin.device_name not in self.active_per_device:
            self.active_per_device[with_bin.device_name] = False
        self.bytes_per_destination_per_device[with_bin.device_name][
            with_bin.fivetuple[0] if with_bin.fivetuple[0] != with_bin.device_name else with_bin.fivetuple[1]
        ] += with_bin.size

    def finish(self, before_this_bin: Bin):
        self.to_microsecs = before_this_bin.microsecs
        self.to_time = before_this_bin.time

    def to_dict(self):
        return {
            "_from": [self.from_time, self.from_microsecs],
            "_to": [self.to_time, self.to_microsecs],
            "devices": {
                device_name: {
                    "active": self.active_per_device[device_name],
                    "destinations": [
                        {
                            "dest": dest,
                            "size": size
                        }
                        for dest, size in sorted(
                            [(dest, size) for dest, size in destinations.items()],
                            key=lambda pair: pair[1],
                            reverse=True)[:4]  # Up to 3 top destination entries
                    ]
                }
                for device_name, destinations in self.bytes_per_destination_per_device.items()
            }
        }


class ActivityIntervals:

    def __init__(self, activity_file_path):
        self.activity_file_path = activity_file_path
        self.parsed = False
        self.intervals: List[ActivityInterval] = []
        if os.path.exists(activity_file_path):
            self.parse()

    def init_activity_file(self, bin_file_path):
        self.intervals = []
        current_interval: Optional[ActivityInterval] = None
        with open(bin_file_path, 'r') as bin_file:
            for i, line in enumerate(bin_file):
                if i > 0:  # Skip header
                    next_bin = Bin.from_row(line)
                    if current_interval and next_bin.microsecs - current_interval.from_microsecs > flow.MAX_BIN_AGE:
                        current_interval.finish(next_bin)
                        current_interval = None
                    if not current_interval:
                        current_interval = ActivityInterval()
                        self.intervals.append(current_interval)
                    current_interval.update(next_bin)
        self.store()

    def store(self):
        with open(self.activity_file_path, 'w') as activity_file:
            yaml.dump([
                activity_interval.to_dict()
                for activity_interval in self.intervals
            ], activity_file)

    def parse(self):
        with open(self.activity_file_path, 'r') as activity_file:
            content = yaml.load(activity_file)
        self.intervals = [
            ActivityInterval.from_dict(interval_dict)
            for interval_dict in content
        ]
        self.parsed = True

    def active_at_this_time(self, time: int, device: str):
        if not self.parsed:
            return False
        for i in range(len(self.intervals)):
            if i + 1 == len(self.intervals) or self.intervals[i + 1].from_microsecs > time:
                return self.intervals[i].active_per_device[device]
