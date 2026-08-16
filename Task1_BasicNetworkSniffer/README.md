Basic Network Sniffer

-----
Project Overview
The Basic Network Sniffer is a Python application developed using the Scapy library. It captures live network packets and displays useful information about each packet, helping users understand how network communication works.

This project was completed as Task 1 of the CodeAlpha Cyber Security Internship.

-----
Objectives 
Capture live network traffic.
Analyze packet information.
Display important network details.
Learn the basics of network protocols.

-----
Features
Capture live packets in real time.
Display packet number.
Display capture date and time.
Display source and destination IP addresses.
Detect protocol (TCP, UDP, ICMP).
Display source and destination ports.
Display packet payload (when available).

-----
Technologies Used
*Python 3
*Scapy
*Visual Studio Code

-----
Project Structure

Task1_BasicNetworkSniffer/
│
├── sniffer.py
├── requirements.txt
├── README.md
└── screenshots/


-----
Installation

1. Clone the repository:
git clone https://github.com/Maroua-a/codealpha_tasks.git


2. Navigate to the project folder:
cd codealpha_tasks/Task1_BasicNetworkSniffer


3. Install the required package:
pip install -r requirements.txt


-----
Running the Project

Run the following command:
python sniffer.py


Press **Ctrl + C** to stop capturing packets.

-----
Sample Output

==============================
Packet Number   : 1
Time            : 2026-08-02 18:30:15
Source IP       : 192.168.1.7
Destination IP  : 20.184.175.17
Protocol        : TCP
Source Port     : 51803
Destination Port: 443
Packet Length   : 74 bytes
Payload         : No Payload


--------
Author
**Kachroud Maroua**

CodeAlpha Cyber Security Internship – August 2026
