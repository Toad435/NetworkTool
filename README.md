# Network and System Multitool
This is a command-line multitool that provides a wide range of functionalities for network troubleshooting, system information retrieval, and security-related tasks. It is designed to run on Windows using batch scripting. The tool contains 41 options for performing various tasks such as pinging IPs, performing DNS lookups, scanning ports, checking system information, and even executing network penetration testing commands.

# Features
The multitool includes the following features:

Ping an IP Address
Show current IP Address
Traceroute to a Domain or IP
Show Network Configuration (IPConfig)
Shutdown a Remote Computer
Test Wi-Fi Signal Strength
Get Website Information
Nmap Port Scan
Angry IP Scanner
Clear the Screen
Trigger a Blue Screen (Admin required)
Check Server Status (Ping)
DNS Lookup
Show System Information
Check Disk Space
Check for Windows Updates
Show Environment Variables
Show Network Statistics
Check Running Processes
Create a Scheduled Task
Show Installed Software
Get System Boot Time
Monitor CPU Usage
Monitor RAM Usage
Kill a Running Process
Generate a System Report
Whois Lookup
Subdomain Enumeration
SSL/TLS Certificate Info
Reverse DNS Lookup
Network Vulnerability Scan (Nmap)
Perform Dictionary Attack (Hydra)
DNS Zone Transfer
Network Sniffer (Wireshark)
Metasploit Framework
ARP Spoofing
SQL Injection Test
Cross-Site Scripting (XSS) Attack
FTP Bounce Attack
Wireless Network Cracking
DDoS Test (broken)
Prerequisites
Before using the multitool, ensure that you have the following prerequisites:

Administrative privileges are required for certain features such as shutting down remote computers and triggering a Blue Screen.
Angry IP Scanner must be installed in the same directory for the Angry IP Scanner option.
Wireshark must be installed for network sniffing.
Metasploit must be installed for the Metasploit option.
Hydra, Aircrack-ng, SQLmap, and other security tools must be installed to run penetration tests like Dictionary Attack, Wireless Network Cracking, etc.
Usage
To use the tool:

Download or copy the script to your Windows machine.
Run the batch file as an Administrator to ensure all features work correctly.
You will be presented with a menu containing all available options.
Choose an option by entering the corresponding number (1-41).
Follow the prompts for each option to provide necessary inputs and execute the desired task.
Example Usage:
Ping an IP Address:

Choose option 1 and input the IP or domain to ping, e.g., 8.8.8.8 or google.com.
Nmap Port Scan:

Choose option 8 and then select the scan type (Quick, Full, Version Detection, OS Detection).
Whois Lookup:

Choose option 27 and input the domain name to look up.
SQL Injection Test:

Choose option 37 and provide the target URL to test for SQL injection vulnerabilities.
Notes:
Some features may not be compatible with all Windows versions. Ensure your system is up-to-date.
The script uses third-party tools like Nmap, Hydra, Wireshark, and Metasploit, so ensure these tools are installed in the system PATH or in the same directory as the script.
The DDoS and some penetration testing options should only be used in legal and authorized environments to prevent illegal activities.
Disclaimer
This tool is intended for educational and ethical use only. It is essential to ensure that all actions performed with this script are authorized and legal in your jurisdiction. The author is not responsible for any misuse of this tool. Always obtain explicit permission before performing any security tests or attacks on networks and systems.

Credits:
Toad for coding.
Nebula for the big text formatting.
Various open-source projects for providing the tools used in this script (e.g., Nmap, Hydra, Metasploit).
