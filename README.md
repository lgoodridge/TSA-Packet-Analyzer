# TSA Packet Analyzer

A packet analyzer for tracking geographic and security information.

## Installation

### Windows

At this time, Windows is not supported (sorry).

### Mac OS X / Linux

Download and compile the ```p0f3``` tool:
```
wget http://lcamtuf.coredump.cx/p0f3/releases/p0f-3.09b.tgz
tar -xzvf p0f-3.09b.tgz
cd p0f-3.09b
make
```

### All Platforms

Clone this repository, and install the remaining dependencies:
```
git clone https://github.com/lgoodridge/TSA-Packet-Analyzer.git
cd TSA-Packet-Analyzer
pip install -r requirements.txt
```

Finally, you will need to update the ```settings.ini``` file to match the setup of your system. In particular, make sure that:
 * p0f: DatabaseFilePath points to your ```pof.fp``` file (or you've symbolic linked it to a location in your PATH, and the setting is left as 'default')
 * CaptureInterface is set to the network interface to capture packets on if UseLiveCapture is set.
 *  InitFileLocation is set a ```.pcap``` file to read from if UseLiveCapture is not set

## Project Structure

This project is organized into three layers, with each layer relying on methods implemented in the previous one.

#### capturer:

Responsible for capturing packets online, or reading them from a provided .pcap file and parsing them into a format more usable by the rest of the project. This layer exposes a ```TSA_Packet``` abstraction, which is a stripped down packet containing only the fields we need, and a ```TSA_Stream``` abstraction which is used for efficient querying of the most recently captured packets.

#### analyzer:

Responsible for aggregating the packet data, interpreting it, and converting it to a format easily used by the visualizer. In particular, this layer uses several other external APIs to make additional inferences on the packet stream, such as which countries the packets are being routed to, or whether a host may potentially be the victim of a cyberattack.

#### visualizer:

Responsible for displaying the data outputted by the analyzer in a clean, and intuitive manner. This layer performs some minimal pre-processing, then displays the data in a Plotly dashboard.
