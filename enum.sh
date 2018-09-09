#!/bin/bash

# No Color
NC='\033[0m'

# Regular Colors
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue

# Bold
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue

hup () {
	echo -e "${BRed}[!] Killing everything and exiting${NC}"
	stty sane
	exit
}

int () {
	kill -HUP -$$
}

init () {
	cd $1
	echo -e "${BBlue}[-] $ip: Performing basic NMap Scan${NC}"
	nmap $1 -oN nmap-init > /dev/null
	nmap $1 -sU -p 160,161 -oN nmap-init --append-output > /dev/null
	echo -e "${BBlue}[-] $ip: Basic NMap Scan complete${NC}"
	for port in $(cat nmap-init | grep open | cut -d' ' -f1 | cut -d'/' -f1)
	do
		if [ $port == "80" ]; then
			echo -e "${BGreen}[i] $ip: Port 80 open. Running Dirb and Nikto${NC}"
			nikto -h $ip -Save=nikto > nikto.txt &
			sleep 3s
			dirb "http://$ip" -o dirb.txt > /dev/null &
			if [[ $(cat nikto.txt | grep Server) == *"Apache"* ]]; then
				dirb "http://$ip" /usr/share/dirb/wordlists/vulns/apache.txt,/usr/share/dirb/wordlists/vulns/tests.txt -o dirb-server.txt > /dev/null &
			elif [[ $(cat nikto.txt | grep Server) == *"IIS"* ]]; then
				dirb "http://$ip" /usr/share/dirb/wordlists/vulns/iis.txt,/usr/share/dirb/wordlists/vulns/tests.txt -o dirb-server.txt > /dev/null &
			fi
		fi
		if [ $port == "8080" ]; then
			echo -e "${BGreen}[i] $ip: Port 8080 open. Running Dirb and Nikto${NC}"
			nikto -h "http://$ip:8080" -Save=nikto > nikto.txt &
			sleep 3s
			dirb "http://$ip:8080" -o dirb.txt > /dev/null &
			if [[ $(cat nikto.txt | grep Server) == *"Apache"* ]]; then
				dirb "http://$ip:8080" /usr/share/dirb/wordlists/vulns/apache.txt,/usr/share/dirb/wordlists/vulns/tests.txt -o dirb-server.txt > /dev/null &
			elif [[ $(cat nikto.txt | grep Server) == *"IIS"* ]]; then
				dirb "http://$ip:8080" /usr/share/dirb/wordlists/vulns/iis.txt,/usr/share/dirb/wordlists/vulns/tests.txt -o dirb-server.txt > /dev/null &
			fi
		fi
		if [ $port == "443" ]; then
			echo -e "${BGreen}[i] $ip: Port 443 open. Running Dirb and Nikto${NC}"
			nikto -h "https://$ip" -Save=nikto-443 > nikto-443.txt &
			sleep 3s
			dirb "https://$ip" -o dirb-443.txt > /dev/null &
			if [[ $(cat nikto.txt | grep Server) == *"Apache"* ]]; then
				dirb "https://$ip" /usr/share/dirb/wordlists/vulns/apache.txt,/usr/share/dirb/wordlists/vulns/tests.txt -o dirb-server-443.txt > /dev/null &
			elif [[ $(cat nikto.txt | grep Server) == *"IIS"* ]]; then
				dirb "https://$ip" /usr/share/dirb/wordlists/vulns/iis.txt,/usr/share/dirb/wordlists/vulns/tests.txt -o dirb-server-443.txt > /dev/null &
			fi
		fi
		if [ $port == "139" ]; then
			echo -e "${BGreen}[i] $ip: Port 139 open. Running smb enums and enum4linux${NC}"
			nmap -vvv $ip -sV -p 139,445 --script smb-enum*,smb-vuln* -oN nmap-smb > /dev/null
			enum4linux -v $ip > enum4linux.txt 2>/dev/null &
		fi
		if [ $port == "25" ]; then
			echo -e "${BGreen}[i] $ip: Port 139 open. Running smb enums and enum4linux${NC}"
			nmap -vvv $ip -sV -p 25,110 --script smtp-enum*,smtp-vuln* -oN nmap-smtp > /dev/null
		fi
		if [ $port == "161" ]; then
			echo -e "${BGreen}[i] $ip: Port 161 open. Runnning nmap, snmpwalk, onesixtyone${NC}"
			nmap -vvv $ip -sV -sU -p 160,161 --script snmp-win32*,snmp-sys*,snmp-proc* -oN nmap-snmp > /dev/null
			snmpwalk -c public -v1 $ip > snmpwalk.txt &
			onesixtyone $ip > onesixtyone.txt &
		fi
		if [ $port == "21" ]; then
			echo -e "${BGreen}[i] $ip: Port 21 open. Checking Anonymous login and vuln${NC}"
			nmap -vvv $ip -p 20,21 -sV --script ftp-anon,ftp-vuln* -oN nmap-ftp > /dev/null
		fi
	done
	echo -e "${BBlue}[-] $ip: Starting aggressive scan${NC}"
	nmap -vvv $ip -A -oN nmap-A > /dev/null
}

trap hup HUP
trap int INT

exec 2>/dev/null

echo -e "${BYellow}[*] You did arrange IPs as per preference, right?${NC}"

for ip in $(cat ips.txt)
do
	if [ ! -d "$ip" ]; then
		echo -e "${BBlue}[-] Creating directory $ip${NC}"
		mkdir $ip
	fi
	init $ip &
done
wait
echo -e "${BGreen}[i] Basic and Aggressive scans complete${NC}"
for ip in $(cat ips.txt)
do
	cd $ip
	echo -e "${BBlue}[-] $ip: Starting all port scan${NC}"
	nmap $ip -p- -oN nmap-all > /dev/null
	echo -e "${BBlue}[-] $ip: Starting UDP scan${NC}"
	nmap $ip -sU -oN nmap-sU > /dev/null
	cd ..
done
echo -e "${BGreen}[i] Completed all scans${NC}"
stty sane
