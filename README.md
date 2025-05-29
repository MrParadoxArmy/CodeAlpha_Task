# Basic Network Sniffer

![Project Screenshot](1000395792.jpg)

## Overview

This project is a **Basic Network Sniffer** built in Python. It captures and analyzes network traffic in real time. By working on this project, you'll gain hands-on experience with how data flows on a network and how network packets are structured.

## Features

- Capture live packets from a network interface.
- Parse and display Ethernet, IP, TCP/UDP packet headers.
- Analyze and log traffic for inspection.
- Modular structure with components for sniffing and handling connections.

## Files

- `main.py` – Entry point to start the sniffer.
- `sniffer.py` – Captures and decodes packets.
- `connections.py` – Manages connection tracking or filtering logic.
- `README.md` – Project documentation (you’re reading it!).

## Getting Started

### Requirements

- Python 3.x
- Administrator/root privileges (for raw socket access)

### Run the Sniffer

```bash
sudo python3 main.py
