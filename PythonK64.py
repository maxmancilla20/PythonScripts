# echo-client.py

import socket
HOST = "192.168.0.102" # The server's IP address
PORT = 7 # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b"Are you there?")
    data = s.recv(1024)
print(f"Received {data!r}")

""" ========

The lwip_tcpecho demo application demonstrates a TCP echo demo on the lwIP TCP/IP stack with bare metal KSDK or
FreeRTOS. The demo uses the TCP protocol and acts as an echo server. The application sends back the received TCP
packets from the PC, which can be used to test whether a TCP connection is available.


Toolchain supported
===================
- IAR embedded Workbench  9.10.2
- Keil MDK  5.34
- GCC ARM Embedded  10.2.1
- MCUXpresso  11.5.0

Hardware requirements
=====================
- Mini/micro USB cable
- RJ45 Network cable
- FRDM-K64F board
- Personal Computer

Board settings
==============
No special settings are required.

Prepare the Demo
================
1.  Connect a USB cable between the PC host and the OpenSDA(or USB to Serial) USB port on the target board.
2.  Open a serial terminal on PC for OpenSDA serial(or USB to Serial) device with these settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control
3.  Insert the Ethernet Cable into the target board's RJ45 port and connect it to your PC network adapter.
4.  Configure the host PC IP address to 192.168.0.100.
5.  Download the program to the target board.
7.  Either press the reset button on your board or launch the debugger in your IDE to begin running the demo.

Running the demo
================
1. When the demo runs, the log would be seen on the terminal like:
		Initializing PHY...

		************************************************
		 TCP Echo example
		************************************************
		 IPv4 Address     : 192.168.0.102
		 IPv4 Subnet mask : 255.255.255.0
		 IPv4 Gateway     : 192.168.0.100
		************************************************
2. From the command window, type echotool 192.168.0.102 /p tcp /r 7 /d hello
	NOTE: The echotool.exe application can be found here https://github.com/PavelBansky/EchoTool
3. The command window should get response:
		Hostname 192.168.0.102 resolved as 192.168.0.102

		Reply from 192.168.0.102:7, time 1 ms OK
		Reply from 192.168.0.102:7, time 0 ms OK
		Reply from 192.168.0.102:7, time 1 ms OK
		Reply from 192.168.0.102:7, time 0 ms OK
		Reply from 192.168.0.102:7, time 0 ms OK

		Statistics: Received=5, Corrupted=0"""
