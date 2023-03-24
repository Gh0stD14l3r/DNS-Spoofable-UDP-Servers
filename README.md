# DNS Spoofable UDP Servers

## What is this
This is a tool that will grab all public dns server IP Addresses then send a UDP request to all of them.
If any respond we are able to send spoofable UDP packets. To see more about post exploitation go here

```
https://github.com/Gh0stD14l3r/DNS-Amplification-DDOS
```

## Installation
```
- Download or clone the repository
- Install requirements
-- pip install wget
-- pip install scapy
```

## Usage
```
python dns-spoofable.py -o output_filename
eg. python dns-spoofable.py -o myDNSServers.txt
```
