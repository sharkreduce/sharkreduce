from argparse import ArgumentParser
from collections import defaultdict

from progress.bar import Bar
from . import flow
from .packet import Packet
from .device import DeviceCollection
from .activity import ActivityIntervals

parser = ArgumentParser()
parser.add_argument("source", help="Original tshark export TSV file.")
parser.add_argument("destination", help="Destination TSV file.")
parser.add_argument("-t", "--threshold", type=int, help="Maximum bin age in microseconds.")
parser.add_argument("-n", "--names", help="""Path to a YAML file which contains MAC address specs. Example:
    router:
      - aa:60:b6:43:35:64
      - MacMcMacFace.local
    devices:
      iPhone:
        - 62:84:bd:67:4c:93
      SmartTv2017:
        - LGInnote_61:63:05
    unclassified:
    ignore:
""")
parser.add_argument("-a", "--activity-file", help="Path to activity YAML file.", default="activity.yaml")
parser.add_argument("-i", "--init-activity", action="store_true", default=False, help="""
    Set this flag to write the initial activity file from the *destination TSV file argument*.
""".strip())
args = parser.parse_args()

if args.threshold:
    flow.MAX_BIN_AGE = args.threshold

devices: DeviceCollection = DeviceCollection(args.names)
activity: ActivityIntervals = ActivityIntervals(args.activity_file)

if args.init_activity:
    print(f"Initialising activity file {args.activity_file}...")
    activity.init_activity_file(args.destination)
else:
    line_count = 0
    with open(args.source, 'r') as in_file:
        for line in in_file:
            line_count += 1

    with open(args.source, 'r') as in_file:
        with open(args.destination, 'w') as out_file:

            progress_bar = Bar("Reducing", max=line_count, check_tty=False)
            flow.Bin.print_headers(out_file)

            for i, line in enumerate(in_file):
                packet = Packet(line, i)
                device = devices[packet]
                if not device:
                    continue
                devices.flush_bins(out_file, time=packet.time)
                device.update(packet, out_file, activity)
                if not (i % 1000):
                    progress_bar.next(n=1000)

            progress_bar.goto(line_count)
            progress_bar.finish()
            devices.flush_bins(out_file, force=True)
            devices.store()
