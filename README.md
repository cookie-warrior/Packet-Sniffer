# Packet Sniffer Tool

This Packet Sniffer Tool is built using Python and is designed to monitor real-time network packets. It can capture and display detailed information for various types of packets, including TCP, UDP, HTTP, and HTTPS.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Technologies](#technologies)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features

- Real-time monitoring of network packets
- Captures TCP, UDP, HTTP, and HTTPS packets
- Displays detailed information for each packet including time, source, source port, destination, destination port, protocol, length, flags, and additional info
- User-friendly interface with options to start and stop sniffing, clear the display, and apply protocol filters

## Installation

### Prerequisites

- Python 3.x installed on your machine
- 
### Steps

1. Clone the repository:
   bash
   git clone https://github.com/cookie-warrior/packet-sniffer-tool.git
   cd packet-sniffer-tool
   
2. Run the application:
   bash
   python main.py
   
## Usage

1. Open the application:
   bash
   python main.py
   

2. Use the buttons on the UI to start and stop sniffing.
3. Enter protocol filters to capture specific types of packets (e.g., TCP, UDP, HTTP, ICMP).
4. View the captured packet information in the table.

## Screenshot

![psniffer](https://github.com/user-attachments/assets/afee47eb-e812-4cfa-a2ce-fd2d3894e94a)

## Technologies

- Python
- Scapy (for packet capturing)
- pyqt5 (for GUI)

Thank you for using the Packet Sniffer Tool! We hope you find it useful and educational.
