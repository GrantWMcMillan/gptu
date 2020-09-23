#!/bin/bash

###############################################################
##### Written by Grant McMillan                              ##
##### Grant's Pen-Testing Utilities - Nmap/Nikto/Eyewitness  ##
##### March/September  2020                                  ##
##### Verion 1.2009 = Sept 2020                              ##
###############################################################

#################################################################
# Variables
###############################################################
Files="$1"
input=""
dom=""
dte=$(date +%m-%d-%y)
# Regular Colors
black='\033[0;30m'        # Black
red='\033[0;31m'          # Red
green='\033[0;32m'        # Green
yellow='\033[0;33m'       # Yellow
blue='\033[0;34m'         # Blue
purple='\033[0;35m'       # Purple
cyan='\033[0;36m'         # Cyan
white='\033[0;37m'        # White
# Bold
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow                                                                                                                                                                                                         
BBlue='\033[1;34m'        # Blue                                                                                                                                                                                                           
BPurple='\033[1;35m'      # Purple                                                                                                                                                                                                         
BCyan='\033[1;36m'       # Cyan                                                                                                                                                                                                            
BWhite='\033[1;37m'     # White                                                                                                                                                                                                            
nc="\e[0m"                                                                                                                                                                                                                                 
divide=":"                                                                                                                                                                                                                                 
rootid=$(id -u)                                                                                                                                                                                                                            
################################################################                                                                                                                                                                           
                                                                                                                                                                                                                                           
clear                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                           
banner () {                                                                                                                                                                                                                                
                                                                                                                                                                                                                                           
printf "$BYellow    _ ____ ____  ____  ____ _  \n"
printf "$BYellow   | | G ||| P ||| T ||| U | |\n"
printf "$BYellow   | |___|||___|||_ _|||__ | |\n"
printf "$BYellow   |_/___\|/___\|/___\|/___\_|\n${nc}"
printf "$BRed Grant's Pen-Testing Utilities\n${nc}"
printf "$red Verion 1.2009 \n${nc}"
printf " \n"

echo " "

}
echo " "

if [ -z "$1" ]; then 
        echo ""
        printf "$BRed[X}
		Please enter a valid file!"
        echo ""
        exit 1
fi

if [ "$1" == "-help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        echo " Execute the script and provice the file"
        echo " ./gptu file.txt"
        exit 1
fi

#################################################################################################
#FUNCTIONS
################################################################################################

IPValid () {
ip=$1
oct1=$(echo $ip | cut -d "." -f1)
oct2=$(echo $ip | cut -d "." -f2)
oct3=$(echo $ip | cut -d "." -f3)
oct4=$(echo $ip | cut -d "." -f4)

if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ $oct1 -ge 0 && $oct1 -le 255 ]] && [[ $oct2 -ge 0 && $oct2 -le 255 ]] && [[ $oct3 -ge 0 && $oct3 -le 255 ]] && [[ $oct4 -ge 0 && $oct4 -le 255 ]]; then
  printf "$BGreen[+] $ip Is Valid \n${nc}"
  echo $ip >> $customer/Scope_Valid.txt
  sleep 1
 else
  printf "$BRed[X} $ip is INVALID! \n${nc}"
  echo $ip >> $customer/INVALID.txt
  sleep 1
fi
return 0
}

Trace () {
ip=$1
Twho=$(traceroute $ip | awk {'print $3'} | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
last_hop=$(echo "$Twho" | tail -1)
org=$(whois $last_hop | grep org-name)
org1=$(whois $last_hop | grep OrgName)
echo $ip -- $last_hop -- $org  $org1 >> $customer/Whois.txt
}


ip=$1
Scan_UDP () {
echo ""
printf "$BBlue[+] UDP Scanning $ip  - ( $count / $udp_tot ) -----------------------${nc}"
echo ""
nmap -Pn -sU -sV $ip -oA $customer/Scans/UDP/$ip >/dev/null
echo ""

# pull service ports and output to Master files ready for enumeration.
if [ -f $customer/Scans/UDP/$ip.nmap ]; then
        cat $customer/Scans/UDP/$ip.nmap | grep -w "open " | cut -d / -f1 > $customer/Scans/UDP/$ip_open.txt
fi


# ALL Open ports Master File
if [ -f $customer/Scans/UDP/$ip_open.txt ]; then
        for x in `cat $customer/Scans/UDP/$ip_open.txt`; do 
                IP_all="$ip$divide$x"
                echo $IP_all >> $customer/UDP_Master.txt
        done
fi

if [ -f $customer/Scans/UDP/$ip_open.txt ]; then
        rm $customer/Scans/UDP/$ip_open.txt
fi

let "count=count+1"

}


Nmap_scan () {
ip=$1
#Scan
printf "$BBlue[+] TCP Scanning $ip  - ( $count / $tcp_tot ) \n${nc}"

nmap -Pn -sV $ip -oA $customer/Scans/$ip >/dev/null # remove stdout

# pull service ports and output to Master files ready for enumeration.
if [ -f $customer/Scans/$ip.nmap ]; then
        cat $customer/Scans/$ip.nmap | grep -w open | cut -d / -f1 > $customer/Scans/open.txt
        cat $customer/Scans/$ip.nmap | grep -w http | cut -d / -f1 > $customer/Scans/http.txt
        cat $customer/Scans/$ip.nmap | grep -w ssl | cut -d / -f1 > $customer/Scans/ssl.txt
        cat $customer/Scans/$ip.nmap | grep -w ftp | cut -d / -f1 > $customer/Scans/ftp.txt
        cat $customer/Scans/$ip.nmap | grep -w ssh | cut -d / -f1 > $customer/Scans/ssh.txt
fi

# Write all ports and services to One file for review.
echo "############################################################" >> $customer/Prt_Sv.txt
echo " " >> $customer/Prt_Sv.txt
echo $ip >> $customer/Prt_Sv.txt
echo " " >> $customer/Prt_Sv.txt
cat $customer/Scans/$ip.nmap | grep -w open >> $customer/Prt_Sv.txt


# ALL Open ports Master File
if [ -f $customer/Scans/open.txt ]; then
        for x in `cat $customer/Scans/open.txt`; do 
                IP_all="$ip$divide$x"
                echo $IP_all >> $customer/Master.txt
        done
fi

# HTTP Master File
if [ -f $customer/Scans/http.txt ]; then
        for x in `cat $customer/Scans/http.txt`; do 
                IP_http="$ip$divide$x"
                echo $IP_http >> $customer/HTTP_Master.txt
        done
fi

# SSL Master File
if [ -f $customer/Scans/ssl.txt ]; then
        for x in `cat $customer/Scans/ssl.txt`; do 
                IP_ssl="$ip$divide$x"
                echo $IP_ssl >> $customer/SSL_Master.txt
        done
fi

# FTP Master File
if [ -f $customer/Scans/ftp.txt ]; then
        for x in `cat $customer/Scans/ftp.txt`; do 
                IP_ftp="$ip$divide$x"
                echo $IP_ftp >> $customer/FTP_Master.txt
        done
fi

# SSH Master File
if [ -f $customer/Scans/ssh.txt ]; then
        for x in `cat $customer/Scans/ssh.txt`; do 
                IP_ssh="$ip$divide$x"
                echo $IP_ssh >> $customer/SSH_Master.txt
        done
fi

#Removing the tmp files for multiple ip/lines
rm $customer/Scans/open.txt
rm $customer/Scans/http.txt
rm $customer/Scans/ssl.txt
rm $customer/Scans/ftp.txt
rm $customer/Scans/ssh.txt

let "count=count+1"
}

Scan_Nikto () {
ip=$1
printf "$BBlue[+] Nikto Scanning $ip  - ( $count / $Nik_tot ) \n"
nikto -h $ip >> $customer/Scans/Nikto/Nikto_$ip.txt

# pulls Webservers from Nikto Scans
if [ -f $customer/Scans/Nikto/Nikto_$ip.txt ]; then
        WebServ=$(cat $customer/Scans/Nikto/Nikto_$ip.txt | grep Server: | cut -d : -f2)
        echo " $ip : $WebServ" >> $customer/WebServer.txt
fi

let "count=count+1"
}

HTTP_Head () {
ip=$1
printf "$BBlue[+] Retrieving HTTP Headers $ip  - ( $count / $HTTPHeader_tot ) \n"
curl -I $ip >> $customer/Scans/HTTP_Headers/HTTP_Head_$ip.txt >/dev/null

let "count=count+1"
}

HTTP_Methods () {
Address=$1
echo " "

ip=$(echo $Address | cut -d : -f1)
port=$(echo $Address | cut -d : -f2)

printf "$BBlue[+] Retrieving HTTP Methods $ip  - ( $count / $HTTPMethods_tot_tot ) \n"
nmap -p$port --script http-methods $ip >> $customer/Scans/HTTP_Methods/HTTP_Methods_$ip.txt >/dev/null

let "count=count+1"
}



Scan_SSH () {
Address=$1
echo " "
printf "$BBlue[+] SSH Enumeration $Address  - ( $count / $SSH_tot ) \n"

ip=$(echo $Address | cut -d : -f1)
port=$(echo $Address | cut -d : -f2)

nmap -p$port --script ssh2-enum-algos $ip -o $customer/Scans/SSH/ssh_$ip.txt >/dev/null

let "count=count+1"
}


Screenshot () {
ip=$1
echo ""
printf "$BBlue[+] HTTP Screenshotting $ip  - ( $count / $EW_tot )  "
echo ""

eyewitness --no-prompt -d $customer/Scans/EyeWitness -f $customer/HTTP_Master.txt >/dev/null

let "count=count+1"
}

NTP_enum () {
ip=$1
echo ""
printf "$BBlue[+] NTP Enumeration $ip  - ( $count / $NTP_tot )  "
echo ""


let "count=count+1"
}

FTP_enum () {
ip=$1
echo ""
printf "$BBlue[+] FTP Enumeration $ip  - ( $count / $FTP_tot )  "
echo ""


let "count=count+1"
}

SMB_enum () {
ip=$1
echo ""
printf "$BBlue[+] SMB Enumeration $ip  - ( $count / $SMB_tot )  "
echo ""


let "count=count+1"
}

################################### - Start of Script - ###############################################
banner

printf "$BYellow Please Enter the Customers Domain name: \n"
read domain

customer="$domain$dte"
echo " "

if [[ $rootid == 0 ]] ; then
        printf "$BYellow Do you wish to Scan UDP? (y/n) \n"
        read Opt_udp
fi
echo " "

printf "$BYellow Do you wish to Traceroute all IPs? (y/n) \n"
read Opt_whois
echo " "

clear
banner
################################## - Folder Checks - ##################################################
# Check for Customer folder

if [ -d $customer ]; then
	printf "$BRed[X} Customer Directory Exists \n"
	exit
fi

if [ ! -d $customer ]; then
        mkdir $customer
        chmod 700 $customer
fi

# Check for Scans folder
if [ ! -d "$customer/Scans" ]; then
        mkdir $customer/Scans
        chmod 700 $customer/Scans
fi

# Check for Scans folder
if [ ! -d "$customer/Services" ]; then
        mkdir $customer/Services
        chmod 700 $customer/Services
fi

#UDP folder
if [ "$Opt_udp" == "y" ]  || [ "$Opt_udp" == "Y" ]; then
        if [ ! -d "$customer/Scans/UDP" ]; then
                mkdir $customer/Scans/UDP
                chmod 777 $customer/Scans/UDP
        fi
fi

# HTTPHead folder
if [ ! -d "$customer/Scans/HTTP_Headers" ]; then
        mkdir $customer/Scans/HTTP_Headers
        chmod 700 $customer/Scans/HTTP_Headers
fi

# HTTPMethoids folder
if [ ! -d "$customer/Scans/HTTP_Methods" ]; then
        mkdir $customer/Scans/HTTP_Methods
        chmod 700 $customer/Scans/HTTP_Methods
fi

# Nikto folder
if [ ! -d "$customer/Scans/Nikto" ]; then
        mkdir $customer/Scans/Nikto
        chmod 700 $customer/Scans/Nikto
fi

# SSH folder
if [ ! -d "$customer/Scans/SSH" ]; then
        mkdir $customer/Scans/SSH
        chmod 700 $customer/Scans/SSH
fi

# EW folder
if [ ! -d "$customer/Scans/EyeWitness" ]; then
        mkdir $customer/Scans/EyeWitness
        chmod 700 $customer/Scans/EyeWitness
fi

#########################################################################################
# Validate Input IPAddreses
########################################################################################

printf "$BYellow---------------------------------- Validating IP Addresses --------------------------------------------\n"
for ips in $(cat $Files); do
        IPValid $ips
done

if [ "$Opt_whois" == "y" ]; then
for ips in $(cat $Files); do
        Trace $ips
done
fi 


###########################################################################################
# Start of Enumeration - Nmap TCP/ UDP, Nikto , Eyewitness.
############################################################################################

## Scan TCP
echo " "
if [ -f $customer/Scope_Valid.txt ]; then
        tcp_tot=$(cat $customer/Scope_Valid.txt | wc -l)
        count=1
		 printf "$BYellow----------------------------------- TCP Scanning ----------------------------------------------------\n"
        for x in `cat $customer/Scope_Valid.txt`; do
                Nmap_scan $x
        done
fi

## Scan UDP
echo " "
if [ "$Opt_udp" == "y" ]  || [ "$Opt_udp" == "Y" ]; then
        if [ -f $customer/Scope_Valid.txt ]; then
        udp_tot=$(cat $customer/Scope_Valid.txt | wc -l)
        count=1
				 printf "$BYellow---------------------------- UDP Scanning ------------------------------------------------\n"
        for x in `cat $customer/Scope_Valid.txt`; do
                Scan_UDP $x
        done
        fi
fi
echo " "
## Scan Nikto
if [ -f $customer/HTTP_Master.txt ]; then
        Nik_tot=$(cat $customer/HTTP_Master.txt | wc -l)
        count=1
        printf "$BYellow---------------------------------- Nikto ------------------------------------------------------------\n"
        echo " "
        for x in `cat $customer/HTTP_Master.txt`; do
                Scan_Nikto $x
        done
fi

sleep 1
echo " "
## Pull Headers(Curl) / HTTP Methods
if [ -f $customer/HTTP_Master.txt ]; then

	## HTTP Headers via Curl
        HTTPHeader_tot=$(cat $customer/HTTP_Master.txt | wc -l)
        count=1
        printf "$BYellow---------------------------------- HTTP Headers -----------------------------------------------------\n"
        echo " "
        for x in `cat $customer/HTTP_Master.txt`; do
                HTTP_Head $x
        done
		
	## HTTP Methods
		HTTPMethods_tot=$(cat $customer/HTTP_Master.txt | wc -l)
        count=1
        printf "$BYellow---------------------------------- HTTP Methods -----------------------------------------------------\n"
        echo " "
		
        for x in `cat $customer/HTTP_Master.txt`; do
                HTTP_Methods $x
        done

fi
echo " "
sleep 1

## Enumerate SSH
if [ -f $customer/SSH_Master.txt ]; then
        SSH_tot=$(cat $customer/SSH_Master.txt | wc -l)
        count=1
        printf "$BYellow---------------------------------- SSH Enumeration ---------------------------------------------------\n"
        echo " "
        for x in `cat $customer/SSH_Master.txt`; do
                Scan_SSH $x
        done
fi

sleep 1
echo " "
## Scan EyeWitness
if [ -f $customer/HTTP_Master.txt ]; then
        EW_tot=$(cat $customer/HTTP_Master.txt | wc -l)
        count=1
        printf "$BYellow------------------------------- HTTP ScreenShots -------------------------------------------------------\n"
        for x in `cat $customer/HTTP_Master.txt`; do
                Screenshot $x
        done
fi
echo " "
exit 0
