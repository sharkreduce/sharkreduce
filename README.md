# SharkReduce 🦈🔻

Utility to convert wireshark captures to useful datasets.

## Installation

```bash
pip install sharkreduce
```

## Steps to create reduced dataset

### Step 1: Export capture using tshark

```bash
tshark -t e -Ndmnt -r all.pcapng -T fields \
  -e frame.time \
  -e eth.src_resolved \
  -e eth.dst_resolved  \
  -e _ws.col.Source \
  -e _ws.col.Destination \
  -e _ws.col.Protocol \
  -e tcp.len \
  -e udp.length \
  -e tcp.srcport \
  -e tcp.dstport \
  -e udp.srcport \
  -e udp.dstport \
  -e _ws.col.Time '(eth.type == 0x800) or (eth.type == 0x86dd)' > reduceme.tsv
```

### Step 2: Fill device id file

Sharkreduce requires a device mac-address map file to create pretty reduced output.

Run it once to pre-fill the file with all mac IDs from your capture:

```bash
python3 -m sharkreduce -t 60000000 -n devices.yaml reduceme.tsv reduced.tsv
```

**Note:** `-t 60000000` means that SharkReduce will create reduced bins of
connections up to 60 seconds.

**Note:** The command will initially create an empty `reduced.tsv`!

The command will create a file called `devices.yaml` which looks like this:

```yaml
devices: []
ignore: {}
unclassified:
  some-mac-adress:
    - dns-name
    - ip-adress
    - etc.
```

For each unclassified mac address, you will see some aliases (IP/Hostname)
which helps you to determine which device the MAC belongs to.

If the MAC belongs to a device you want to analyse, think of a good name
and create an entry under `devices`. Otherwise create an entry under `ignored`.
Do this for all unclassified MACs:

```yaml
devices:
  SuspiciousDevice:
    - some-mac-address
    - some-hostname
  OtherInterestingDevice:
    - other-mac
ignore:
  - router-mac-address
  - broadcast address
```

### Step 3: Create initial reduced output.

Re-run 

```bash
python3 -m sharkreduce -t 60000000 -n devices.yaml reduceme.tsv reduced.tsv
```

This time `reduced.tsv` should have a lot of data in it, with device identifiers
that look very readable to you.

### Step 4: Create/fill activity file

In order to determine activity periods for your devices to correctly
fill the `active_use` column in the reduced output, you have to create an
activity file. You can initialise the file like this:

```bash
python3 -m sharkreduce --init-activity -t 3600000000 -n devices.yaml reduceme.tsv reduced.tsv
```

This will READ from `reduced.tsv` to create a file called `activity.yaml`,
where you can annotate your activity per device in ~1h intervals.

Set the `active` field to True where you think you have been actively using the device.

### Step 5: Re-run sharkreduce with filled activity file

If it exists, sharkreduce will use the content of `activity.yaml` to 
fill the `active_use` column. So you just need to re-run ...

```bash
python3 -m sharkreduce -t 60000000 -n devices.yaml reduceme.tsv reduced.tsv
```

**Note:** If you change the `devices.yaml` you have to re-do steps 3, 4 and 5.

### Step 6: Party! 🥳

Your pretty reduced capture with annotated device names and activity is now
stored under `reduced.tsv`.
