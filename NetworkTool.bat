@echo off
chcp 65001
color 0A

NET SESSION >nul 2>nul
if %errorlevel% neq 0 (
    echo You must run this script as an administrator. Exiting...
    pause
    exit
)

:MENU
cls
color 5
echo.
echo.
echo Credits:
echo Toad for coding
echo Nebula for big text
pause
cls
echo                           ███▄    █ ▓█████▄▄▄█████▓ █     █░ ▒█████   ██▀███   ██ ▄█▀
echo                           ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒▓█░ █ ░█░▒██▒  ██▒▓██ ▒ ██▒ ██▄█▒ 
echo                          ▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░▒█░ █ ░█ ▒██░  ██▒▓██ ░▄█ ▒▓███▄░ 
echo                          ▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░ ░█░ █ ░█ ▒██   ██░▒██▀▀█▄  ▓██ █▄ 
echo                         ▒██░   ▓██░░▒████▒ ▒██▒ ░ ░░██▒██▓ ░ ████▓▒░░██▓ ▒██▒▒██▒ █▄
echo                          ░ ▒░   ▒ ▒ ░░ ▒░ ░ ▒ ░░   ░ ▓░▒ ▒  ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░▒ ▒▒ ▓▒
echo                         ░ ░░   ░ ▒░ ░ ░  ░   ░      ▒ ░ ░    ░ ▒ ▒░   ░▒ ░ ▒░░ ░▒ ▒░
echo                            ░   ░ ░    ░    ░        ░   ░  ░ ░ ░ ▒    ░░   ░ ░ ░░ ░ 
echo                           ░    ░  ░            ░        ░ ░     ░     ░  ░
echo ------------------------------------------------------------------------------------------------
echo                                       https://discord.gg/X9gUj6e2wr
echo                                       NetworkTool made by Toad
echo ------------------------------------------------------------------------------------------------
echo █1. Ping an IP address              █2. Show my current IP address      █3. Traceroute to a domain or IP
echo █4. Show network configuration      █5. Shutdown a remote computer      █6. Test Wi-Fi signal strength
echo █7. Get website information         █8. Scan Ports with Nmap            █9. Scan Network with Angry IP
echo █10. Clear the screen               █11. Get Blue Screen                █12. Check server status (ping)
echo █13. DNS Lookup (IP to domain)      █14. Show system information        █15. Check Disk Space
echo █16. Check for Windows Updates      █17. Show environment variables     █18. Show network statistics
echo █19. Check running processes        █20. Create a Scheduled Task        █21. Show installed software
echo █22. Get system boot time           █23. Monitor CPU usage              █24. Monitor RAM usage
echo █25. Kill a running process         █26. Generate system report         █27. Whois Lookup
echo █28. Subdomain Enumeration          █29. SSL/TLS Certificate Info       █30. Reverse DNS Lookup
echo █31. Network Vulnerability Scan     █32. Perform Dictionary Attack      █33. DNS Zone Transfer
echo █34. Network Sniffer (Wireshark)    █35. Metasploit Framework           █36. ARP Spoofing
echo █37. SQL Injection Test             █38. Cross-Site Scripting (XSS)     █39. FTP Bounce Attack
echo █40. Wireless Network Cracking      █41. DDOS (broken)
echo.
echo -----------------------------------------------------------------------------------------------
set /p choice="Choose an option (1-41): "

if "%choice%"=="1" goto PING
if "%choice%"=="2" goto MY_IP
if "%choice%"=="3" goto TRACEROUTE
if "%choice%"=="4" goto IPCONFIG
if "%choice%"=="5" goto SHUTDOWN
if "%choice%"=="6" goto WIFI_TEST
if "%choice%"=="7" goto WEBSITE_INFO
if "%choice%"=="8" goto NMAP_SCAN
if "%choice%"=="9" goto ANGRY_IP_SCANNER
if "%choice%"=="10" goto CLEAR
if "%choice%"=="11" goto BLUE_SCREEN
if "%choice%"=="12" goto CHECK_SERVER_STATUS
if "%choice%"=="13" goto DNS_LOOKUP
if "%choice%"=="14" goto SYSTEM_INFO
if "%choice%"=="15" goto CHECK_DISK
if "%choice%"=="16" goto CHECK_UPDATES
if "%choice%"=="17" goto ENV_VARS
if "%choice%"=="18" goto NET_STATS
if "%choice%"=="19" goto RUNNING_PROCESSES
if "%choice%"=="20" goto SCHEDULED_TASK
if "%choice%"=="21" goto INSTALLED_SOFTWARE
if "%choice%"=="22" goto BOOT_TIME
if "%choice%"=="23" goto CPU_USAGE
if "%choice%"=="24" goto RAM_USAGE
if "%choice%"=="25" goto KILL_PROCESS
if "%choice%"=="26" goto SYSTEM_REPORT
if "%choice%"=="27" goto WHOIS_LOOKUP
if "%choice%"=="28" goto SUBDOMAIN_ENUM
if "%choice%"=="29" goto CERT_INFO
if "%choice%"=="30" goto REVERSE_DNS
if "%choice%"=="31" goto NETWORK_VULNERABILITY_SCAN
if "%choice%"=="32" goto DICTIONARY_ATTACK
if "%choice%"=="33" goto DNS_ZONE_TRANSFER
if "%choice%"=="34" goto WIRESHARK_SNIFFER
if "%choice%"=="35" goto METASPLOIT
if "%choice%"=="36" goto ARP_SPOOFING
if "%choice%"=="37" goto SQL_INJECTION_TEST
if "%choice%"=="38" goto XSS_ATTACK
if "%choice%"=="39" goto FTP_BOUNCE_ATTACK
if "%choice%"=="40" goto WIRELESS_CRACKING
if "%choice%"=="41" goto DDoS_TEST

echo Invalid choice. Please select an option between 1-41.
pause
goto MENU

:PING
cls
color 0A
echo ------------------------------------------------------
echo           Ping an IP Address
echo ------------------------------------------------------
set /p ip="Enter the IP address or domain to ping (e.g., 8.8.8.8 or google.com): "
if "%ip%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)
echo Pinging %ip%...
ping %ip% -n 4
echo ------------------------------------------
pause
goto MENU

:MY_IP
cls
color 0A
echo ------------------------------------------------------
echo      Show My Current IP Address
echo ------------------------------------------------------
echo Your current local IP address is:
ipconfig | findstr /i "IPv4"
echo ------------------------------------------
pause
goto MENU

:TRACEROUTE
cls
color 0A
echo ------------------------------------------------------
echo        Traceroute to IP/Domain
echo ------------------------------------------------------
set /p target="Enter the domain or IP for traceroute (e.g., google.com or 8.8.8.8): "
if "%target%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)
echo Tracing route to %target%...
tracert %target%
echo ------------------------------------------
pause
goto MENU

:IPCONFIG
cls
color 0A
echo ------------------------------------------------------
echo          Show Network Configuration
echo ------------------------------------------------------
ipconfig /all
echo ------------------------------------------
pause
goto MENU

:SHUTDOWN
cls
color 0A
echo ------------------------------------------------------
echo      Shutdown a Remote Computer
echo ------------------------------------------------------
echo WARNING: You need administrative privileges on the remote machine to perform this action.
set /p ip="Enter the IP address of the remote computer: "
if "%ip%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)
set /p confirm="Are you sure you want to shutdown %ip%? (Y/N): "

if /i "%confirm%"=="Y" (
    echo Shutting down %ip%...
    shutdown /s /f /t 0 /m \\%ip%
    echo Shutdown command sent.
) else (
    echo Shutdown operation canceled.
)

echo ------------------------------------------
pause
goto MENU

:WIFI_TEST
cls
color 0A
echo ------------------------------------------------------
echo        Test Wi-Fi Signal Strength
echo ------------------------------------------------------
echo Checking Wi-Fi connection...
echo ------------------------------------------
netsh wlan show interfaces | findstr /C:"Signal"
echo ------------------------------------------
pause
goto MENU

:WEBSITE_INFO
cls
color 0A
echo ------------------------------------------------------
echo         Get Website Information
echo ------------------------------------------------------
set /p website="Enter the website URL (e.g., example.com): "
if "%website%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)

echo Retrieving information for %website%...

echo IP Address:
for /f "tokens=*" %%a in ('nslookup %website% ^| findstr /i "Address"') do echo %%a

echo ------------------------------------------
echo Headers:
curl -I http://%website%
echo ------------------------------------------
pause
goto MENU

:NMAP_SCAN
cls
color 0A
echo ------------------------------------------------------
echo             Nmap Port Scan & Information
echo ------------------------------------------------------
set /p target="Enter the target IP address or domain (e.g., 192.168.1.1 or google.com): "
if "%target%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)

echo.
echo Choose scan type:
echo 1. Quick Scan (top 100 ports)
echo 2. Full Scan (all ports)
echo 3. Service Version Detection
echo 4. OS Detection
set /p scan_type="Enter choice (1-4): "

if "%scan_type%"=="1" (
    nmap -T4 --top-ports 100 %target%
) else if "%scan_type%"=="2" (
    nmap -T4 %target%
) else if "%scan_type%"=="3" (
    nmap -sV %target%
) else if "%scan_type%"=="4" (
    nmap -O %target%
) else (
    echo Invalid choice. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)

echo ------------------------------------------
pause
goto MENU

:ANGRY_IP_SCANNER
cls
color 0A
echo ------------------------------------------------------
echo        Angry IP Scanner Network Scan
echo ------------------------------------------------------
echo WARNING: Make sure you have Angry IP Scanner installed in the same folder.
echo ------------------------------------------------------
echo Running Angry IP Scanner...
start AngryIPScanner.exe
echo ------------------------------------------
pause
goto MENU

:CLEAR
cls
goto MENU

:BLUE_SCREEN
cls
color 0C
echo ------------------------------------------------------
echo Note: You need to run this as an administrator to trigger a Blue Screen.
echo Also, you will retain all files even after the crash.
echo ------------------------------------------------------
set /p confirm="Are you sure you want to trigger a Blue Screen? (Y/N): "
if /i "%confirm%"=="Y" (
    echo Triggering Blue Screen...
    echo Preparing crash...
    timeout /t 3
    echo Press enter to start BlueScreen!
    pause
    powershell wininit
) else (
    echo Operation canceled. No Blue Screen triggered.
)

echo ------------------------------------------
pause
goto MENU

:CHECK_SERVER_STATUS
cls
color 0A
echo ------------------------------------------------------
echo         Check Server Status (Ping)
echo ------------------------------------------------------
set /p server="Enter the server IP or domain (e.g., 192.168.1.1 or google.com): "
if "%server%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)

echo Checking if %server% is online...
ping %server% -n 1 >nul

if errorlevel 1 (
    echo %server% is offline.
) else (
    echo %server% is online.
)

echo ------------------------------------------
pause
goto MENU

:DNS_LOOKUP
cls
color 0A
echo ------------------------------------------------------
echo            DNS Lookup (IP/Domain)
echo ------------------------------------------------------
set /p dns_input="Enter domain (e.g., google.com) or IP (e.g., 8.8.8.8): "
if "%dns_input%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)

echo Performing DNS lookup for %dns_input%...
nslookup %dns_input%
echo ------------------------------------------
pause
goto MENU

:SYSTEM_INFO
cls
color 0A
echo ------------------------------------------------------
echo          System Information (CPU, Memory)
echo ------------------------------------------------------
systeminfo | findstr /C:"Total Physical Memory" /C:"Processor"
echo ------------------------------------------
pause
goto MENU

:CHECK_DISK
cls
color 0A
echo ------------------------------------------------------
echo          Check Disk Space
echo ------------------------------------------------------
echo Checking disk space on all drives...
wmic logicaldisk get caption, description, freespace, size
echo ------------------------------------------
pause
goto MENU

:CHECK_UPDATES
cls
color 0A
echo ------------------------------------------------------
echo          Check Windows Updates
echo ------------------------------------------------------
echo Checking for available Windows updates...
powershell -command "Get-WindowsUpdate"
echo ------------------------------------------
pause
goto MENU

:ENV_VARS
cls
color 0A
echo ------------------------------------------------------
echo          Show Environment Variables
echo ------------------------------------------------------
echo Displaying all environment variables...
set
echo ------------------------------------------
pause
goto MENU

:NET_STATS
cls
color 0A
echo ------------------------------------------------------
echo          Network Statistics
echo ------------------------------------------------------
echo Displaying network statistics...
netstat -ano
echo ------------------------------------------
pause
goto MENU

:RUNNING_PROCESSES
cls
color 0A
echo ------------------------------------------------------
echo          Running Processes
echo ------------------------------------------------------
echo Displaying all running processes...
tasklist
echo ------------------------------------------
pause
goto MENU

:SCHEDULED_TASK
cls
color 0A
echo ------------------------------------------------------
echo          Create a Scheduled Task
echo ------------------------------------------------------
set /p task_name="Enter task name: "
set /p task_command="Enter task command (e.g., C:\Windows\System32\notepad.exe): "
echo Creating scheduled task...
schtasks /create /tn "%task_name%" /tr "%task_command%" /sc once /st 00:00
echo Task created successfully.
echo ------------------------------------------
pause
goto MENU

:INSTALLED_SOFTWARE
cls
color 0A
echo ------------------------------------------------------
echo          Show Installed Software List
echo ------------------------------------------------------
echo Displaying installed software...
wmic product get name
echo ------------------------------------------
pause
goto MENU

:BOOT_TIME
cls
color 0A
echo ------------------------------------------------------
echo          Get System Boot Time
echo ------------------------------------------------------
echo System Boot Time:
systeminfo | find "Boot Time"
echo ------------------------------------------
pause
goto MENU

:CPU_USAGE
cls
color 0A
echo ------------------------------------------------------
echo          Monitor CPU Usage
echo ------------------------------------------------------
echo Fetching CPU usage statistics...
wmic cpu get loadpercentage
echo ------------------------------------------
pause
goto MENU

:RAM_USAGE
cls
color 0A
echo ------------------------------------------------------
echo          Monitor RAM Usage
echo ------------------------------------------------------
echo Fetching memory usage details...
wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /Value
echo ------------------------------------------
pause
goto MENU

:KILL_PROCESS
cls
color 0A
echo ------------------------------------------------------
echo          Kill a Running Process
echo ------------------------------------------------------
tasklist
echo ------------------------------------------
set /p proc_name="Enter the name of the process to kill: "
if "%proc_name%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)
echo Terminating process %proc_name%...
taskkill /im "%proc_name%" /f
echo Process terminated successfully (if it existed).
echo ------------------------------------------
pause
goto MENU

:SYSTEM_REPORT
cls
color 0A
echo ------------------------------------------------------
echo          Generate a Detailed System Report
echo ------------------------------------------------------
set /p filename="Enter the name of the file to save the report (e.g., report.txt): "
if "%filename%"=="" (
    set filename="system_report.txt"
)
echo Generating system report...
systeminfo > "%filename%"
echo Report saved as %filename%.
echo ------------------------------------------
pause
goto MENU

:WHOIS_LOOKUP
cls
color 0A
echo ------------------------------------------------------
echo                 Whois Lookup for a Domain
echo ------------------------------------------------------
set /p domain="Enter the domain name (e.g., example.com): "
if "%domain%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)

echo Performing Whois lookup for %domain%...
whois %domain%
echo ------------------------------------------
pause
goto MENU

:SUBDOMAIN_ENUM
cls
color 0A
echo ------------------------------------------------------
echo             Subdomain Enumeration
echo ------------------------------------------------------
set /p target_domain="Enter the target domain (e.g., example.com): "
if "%target_domain%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)

echo Enumerating subdomains for %target_domain%...
python -m sublist3r -d %target_domain%
echo ------------------------------------------
pause
goto MENU

:CERT_INFO
cls
color 0A
echo ------------------------------------------------------
echo             SSL/TLS Certificate Info
echo ------------------------------------------------------
set /p cert_domain="Enter the domain name (e.g., example.com): "
if "%cert_domain%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)

echo Fetching SSL/TLS Certificate Information...
echo | openssl s_client -showcerts -servername %cert_domain% -connect %cert_domain%:443
echo ------------------------------------------
pause
goto MENU

:REVERSE_DNS
cls
color 0A
echo ------------------------------------------------------
echo             Reverse DNS Lookup
echo ------------------------------------------------------
set /p ip_address="Enter the IP address (e.g., 8.8.8.8): "
if "%ip_address%"=="" (
    echo No input detected. Returning to menu...
    timeout /t 2 >nul
    goto MENU
)

echo Performing Reverse DNS lookup for %ip_address%...
nslookup %ip_address%
echo ------------------------------------------
pause
goto MENU

:NETWORK_VULNERABILITY_SCAN
cls
color 0A
echo ------------------------------------------------------
echo       Perform Network Vulnerability Scan (Nmap)
echo ------------------------------------------------------
set /p target="Enter target IP or domain for vulnerability scan: "
nmap -sV --script vuln %target%
echo ------------------------------------------
pause
goto MENU

:DICTIONARY_ATTACK
cls
color 0A
echo ------------------------------------------------------
echo       Perform Dictionary Attack (Hydra)
echo ------------------------------------------------------
set /p target="Enter target service (e.g., ssh, ftp, http): "
set /p username="Enter username: "
set /p wordlist="Enter path to wordlist (e.g., /usr/share/wordlists/rockyou.txt): "
hydra -l %username% -P %wordlist% %target% %target_service%
echo ------------------------------------------
pause
goto MENU

:DNS_ZONE_TRANSFER
cls
color 0A
echo ------------------------------------------------------
echo       Perform DNS Zone Transfer
echo ------------------------------------------------------
set /p target="Enter domain for DNS zone transfer (e.g., example.com): "
nslookup -type=any %target%
echo ------------------------------------------
pause
goto MENU

:WIRESHARK_SNIFFER
cls
color 0A
echo ------------------------------------------------------
echo       Launch Network Sniffer (Wireshark)
echo ------------------------------------------------------
echo Make sure Wireshark is installed and running.
start wireshark
echo ------------------------------------------
pause
goto MENU

:METASPLOIT
cls
color 0A
echo ------------------------------------------------------
echo       Launch Metasploit Framework
echo ------------------------------------------------------
echo Make sure Metasploit is installed and running.
start msfconsole
echo ------------------------------------------
pause
goto MENU

:ARP_SPOOFING
cls
color 0A
echo ------------------------------------------------------
echo       Perform ARP Spoofing Attack
echo ------------------------------------------------------
set /p target="Enter target IP address: "
echo Spoofing ARP request...
arpspoof -i eth0 -t %target% <gateway_ip>
echo ------------------------------------------
pause
goto MENU

:SQL_INJECTION_TEST
cls
color 0A
echo ------------------------------------------------------
echo       Test for SQL Injection Vulnerability
echo ------------------------------------------------------
set /p url="Enter target URL (e.g., http://example.com/product?id=1): "
sqlmap -u %url% --batch
echo ------------------------------------------
pause
goto MENU

:XSS_ATTACK
cls
color 0A
echo ------------------------------------------------------
echo       Test for Cross-Site Scripting (XSS)
echo ------------------------------------------------------
set /p url="Enter target URL to test for XSS (e.g., http://example.com): "
set /p payload="Enter XSS payload (e.g., <script>alert(1)</script>): "
echo Testing URL %url% with payload %payload%...
curl -X GET "%url%" -d "%payload%"
echo ------------------------------------------
pause
goto MENU

:FTP_BOUNCE_ATTACK
cls
color 0A
echo ------------------------------------------------------
echo       Perform FTP Bounce Attack
echo ------------------------------------------------------
set /p ftp_server="Enter target FTP server address: "
set /p target="Enter target IP or domain: "
echo Performing FTP bounce attack on %ftp_server% towards %target%...
nc -zv %ftp_server% 20-21
echo ------------------------------------------
pause
goto MENU

:WIRELESS_CRACKING
cls
color 0A
echo ------------------------------------------------------
echo       Perform Wireless Network Cracking
echo ------------------------------------------------------
set /p interface="Enter wireless interface (e.g., wlan0): "
set /p target="Enter target network (SSID): "
airmon-ng start %interface%
airodump-ng %interface%
echo ------------------------------------------
pause
goto MENU