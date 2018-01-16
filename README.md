# TSA Packet Analyzer

A packet analyzer for tracking geographic and security information.

![World Map](https://s17.postimg.org/6ayb8jalb/world_plot.png)

![Country Stats](https://s17.postimg.org/vtqnlt1xr/country_stats.png)

## Installation

### Windows

At this time, Windows is not supported (sorry).

### Mac OS X / Linux

Note: if you do not have ```wget``` you can use ```curl -O``` for downloads.

(Linux) Install libpcap development libraries using your system's package manager. For example, on Ubuntu:
```
sudo apt-get install libpcap-dev
```

Download and compile the ```p0f3``` tool:
```
wget http://lcamtuf.coredump.cx/p0f3/releases/p0f-3.09b.tgz
tar -xzvf p0f-3.09b.tgz
cd p0f-3.09b
make
sudo ln -s "($PWD)/p0f" /usr/local/bin/p0f
```

### All Platforms

Download the ```GeoLite2 Country``` Database
```
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz
tar -xzvf GeoLite2-Country.tar.gz
```

Clone this repository, and install the remaining dependencies:
```
git clone https://github.com/lgoodridge/TSA-Packet-Analyzer.git
cd TSA-Packet-Analyzer
pip install -r requirements.txt
```

Finally, you will need to update the ```settings.ini``` file to match the setup of your system. In particular, make sure that:
 * app: UseLiveCapture is set to "yes" or "no", depending on whether you want to analyze a live capture of packets, or statically analyze a previously captured .pcap file.
 * app: CaptureInterface is set to the network interface to capture packets on if UseLiveCapture is set to "yes".
 * app: InitFileLocation is set to a ```.pcap``` file to read from if UseLiveCapture is set to "no".

The defaults provided for the remainder of the settings file should work without further adjustment, but you may change them if you wish:
 * geoip2: DatabaseFilePath should point to the ```.mmdb``` file provided by the GeoLite2-Country database.
 * p0f: DatabaseFilePath should point to the ```pof.fp``` file provided by the p0f tool.
 * p0f: APISocketFilePath should point to a location that can be used for socket communication (the app will create the socket file at that location if it doesn't already exist).

## Project Structure

This project is organized into three layers, with each layer relying on methods implemented in the previous one.

#### capturer:

Responsible for capturing packets online, or reading them from a provided .pcap file and parsing them into a format more usable by the rest of the project. This layer exposes a ```TSA_Packet``` abstraction, which is a stripped down packet containing only the fields we need, and a ```TSA_Stream``` abstraction which is used for efficient querying of the most recently captured packets.

#### analyzer:

Responsible for aggregating the packet data, interpreting it, and converting it to a format easily used by the visualizer. In particular, this layer uses several other external APIs to make additional inferences on the packet stream, such as which countries the packets are being routed to, or whether a host may potentially be the victim of a cyberattack.

#### visualizer:

Responsible for displaying the data outputted by the analyzer in a clean, and intuitive manner. This layer performs some minimal pre-processing, then displays the data in a Plotly dashboard.

## Acknowledgements

This product includes GeoLite2 data created by MaxMind, available from
<a href="http://www.maxmind.com">http://www.maxmind.com</a>.
