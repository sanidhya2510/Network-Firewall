# Network Firewall

The Network Firewall project is a software-based firewall for Linux that allows you to selectively manage network packets received and sent on the device. This firewall is designed for Linux and provides a command-line interface (CLI) for users to interact with the firewall and pass commands to the kernel modules to manage network packets based on various criteria, such as the packet's protocol, source and destination IP addresses, and port number.

## Project Description

The Network Firewall project works with various Linux kernel modules that are injected into the kernel to intercept and manage network packets using Netfilter hook-functions. It operates at the Network and Link Layer, allowing you to enforce rules before or after routing, depending on whether a packet is inbound or outbound. The project provides a flexible command-line interface for interacting with the firewall, making it a powerful tool for network security.

## Features

- Command-line interface (CLI) for interacting with the firewall
- Customizable rules based on:
  - Packet protocol (-p)
  - Source IP address (-s)
  - Destination IP address (-d)
  - Port number (-port)
- Inbound and outbound packet management
- Load and unload kernel modules without recompiling the kernel

## Getting Started

To use the Network Firewall, follow these steps:

1. Clone or download this repository to your Linux machine.

2. Compile the required kernel modules and the CLI by running the provided build scripts.

3. Load the necessary kernel modules into the kernel using the provided scripts.

4. Use the CLI to pass commands to the kernel modules for managing network packets based on your requirements.

5. Enjoy enhanced network security with your custom firewall rules.


## The CLI supports the following commands:

- `add`: Use this command to add a rule for managing packets based on specified criteria. Flags and their values should follow this command.
- `list`: Use this command to list the active firewall rules.
- `clear`: Use this command to clear all firewall rules.
- `remove`: Use this command to remove a specific firewall rule. Provide the rule number as an argument to the `remove` command.

Flags for the `add` command:

- `-p`: Specify the protocol of the packet you want to manage (e.g., `-p tcp` for TCP packets).
- `-s`: Specify the source IP address for managing packets.
- `-d`: Specify the destination IP address for managing packets.
- `-port`: Specify the port number for managing packets.


## Usage

```bash
# Example command to add a rule for managing all packets from 192.168.1.100 to port 80
./cli add -p tcp -s 192.168.1.100 -port 80

# Example command to list active firewall rules
./cli list

# Example command to clear all firewall rules
./cli clear

# Example command to remove a specific firewall rule
./cli remove 1


Created By:
- Darshan Kumar
- Sanidhya Singh
- Sanidhya Bhatia
- Lakshya Joshi
in Computer Networks Laboratory(CSN-341), CSE Department, IIT Roorkee.
 
