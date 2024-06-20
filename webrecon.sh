#!/bin/bash

# Function to install dependencies
install_dependencies() {
    echo "[+] Installing dependencies..."

    # Update package list
    sudo apt update

    # Install golang
    if ! command -v go &> /dev/null; then
        echo "[+] Installing Go..."
        sudo apt install -y golang
    fi

    # Install assetfinder
    if ! command -v assetfinder &> /dev/null; then
        echo "[+] Installing assetfinder..."
        go install github.com/tomnomnom/assetfinder@latest
    fi

    # Install amass
    if ! command -v amass &> /dev/null; then
        echo "[+] Installing amass..."
        sudo apt install -y amass
    fi

    # Install httprobe
    if ! command -v httprobe &> /dev/null; then
        echo "[+] Installing httprobe..."
        go install github.com/tomnomnom/httprobe@latest
    fi

    # Install nikto
    if ! command -v nikto &> /dev/null; then
        echo "[+] Installing nikto..."
        sudo apt install -y nikto
    fi

    # Install subzy
    if ! command -v subzy &> /dev/null; then
        echo "[+] Installing subzy..."
        go install -v github.com/LukaSikic/subzy@latest
    fi

    # Install waybackurls
    if ! command -v waybackurls &> /dev/null; then
        echo "[+] Installing waybackurls..."
        go install github.com/tomnomnom/waybackurls@latest
    fi

    # Install nmap
    if ! command -v nmap &> /dev/null; then
        echo "[+] Installing nmap..."
        sudo apt install -y nmap
    fi

    # Install gowitness
    if ! command -v gowitness &> /dev/null; then
        echo "[+] Installing gowitness..."
        go install github.com/sensepost/gowitness@latest
    fi

    # Install brutespray
    if ! command -v brutespray &> /dev/null; then
        echo "[+] Installing brutespray..."
        go install github.com/x90skysn3k/brutespray@latest
    fi

    # Install jq
    if ! command -v jq &> /dev/null; then
        echo "[+] Installing jq..."
        sudo apt install -y jq
    fi

    # Install gospider
    if ! command -v gospider &> /dev/null; then
        echo "[+] Installing gospider..."
        go install github.com/jaeles-project/gospider@latest
    fi

    # Install ffuf
    if ! command -v ffuf &> /dev/null; then
        echo "[+] Installing ffuf..."
        go install github.com/ffuf/ffuf@latest
    fi

    # Install nuclei
    if ! command -v nuclei &> /dev/null; then
        echo "[+] Installing nuclei..."
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
        echo "[+] Downloading Nuclei templates..."
        nuclei -update-templates
    fi

    # Install whois
    if ! command -v whois &> /dev/null; then
        echo "[+] Installing whois..."
        sudo apt install -y whois
    fi

    # Install Python and ipwhois library
    if ! command -v python3 &> /dev/null; then
        echo "[+] Installing Python3..."
        sudo apt install -y python3 python3-pip
    fi

    if ! python3 -c "import ipwhois" &> /dev/null; then
        echo "[+] Installing ipwhois library..."
        pip3 install ipwhois
    fi

    # Ensure Go binaries are in the PATH
    export PATH=$PATH:~/go/bin
}

# Function to perform ASN lookup
asn_lookup() {
    ip=$1
    echo "[+] Performing ASN lookup for IP: $ip"
    python3 - <<END
import sys
from ipwhois import IPWhois

ip = "$ip"
try:
    obj = IPWhois(ip)
    results = obj.lookup_rdap(asn_methods=["dns", "whois", "http"])
    asn = results.get("asn")
    asn_cidr = results.get("asn_cidr")
    asn_country_code = results.get("asn_country_code")
    asn_description = results.get("asn_description")
    asn_date = results.get("asn_date")
    with open("$url/recon/asn/${ip}_asn.txt", "w") as f:
        f.write(f"ASN: {asn}\nCIDR: {asn_cidr}\nCountry: {asn_country_code}\nDescription: {asn_description}\nDate: {asn_date}\n")
    print(f"ASN lookup for IP {ip} completed successfully.")
except Exception as e:
    print(f"Error: {e}")
END
}

# Function to check if a domain is blocked
is_blocked() {
    domain=$1
    grep -Fxq "$domain" blocked_domains.txt
}

# Run the installation function
install_dependencies

# Main script to create directories and run recon tasks
url=$1

# Create necessary directories
mkdir -p $url/recon/{scans/vulnerabilities,httprobe,potential_takeovers,wayback/{params,extensions},gowitness,brutespray,spider,ffuf,nuclei,summaries,whois,asn}

touch $url/recon/httprobe/alive.txt
touch $url/recon/final.txt

echo "[+] Harvesting subdomains with assetfinder..."
assetfinder $url >> $url/recon/assets.txt
cat $url/recon/assets.txt | grep $url >> $url/recon/final_temp.txt
rm $url/recon/assets.txt

# Remove blocked domains from final list
while read -r domain; do
    if ! is_blocked "$domain"; then
        echo "$domain" >> $url/recon/final.txt
    fi
done < $url/recon/final_temp.txt
rm $url/recon/final_temp.txt

echo "[+] Double checking for subdomains with amass..."
timeout 4m amass enum -d $url >> $url/recon/amass_output.txt

# Extract subdomains and add to final.txt
grep -Eo "([a-zA-Z0-9_-]+\.$url)" $url/recon/amass_output.txt >> $url/recon/amass_temp.txt

# Remove blocked domains from amass results
while read -r domain; do
    if ! is_blocked "$domain"; then
        echo "$domain" >> $url/recon/final.txt
    fi
done < $url/recon/amass_temp.txt
rm $url/recon/amass_temp.txt

# Remove duplicates and sort final.txt
sort -u $url/recon/final.txt -o $url/recon/final.txt

# Remove amass output file
rm $url/recon/amass_output.txt

echo "[+] Probing for alive domains..."
cat $url/recon/final.txt | httprobe -p http:80 -p https:443 -p http:8080 -p http:8000 -p https:10443 | sed -E 's|https?://||; s|:[0-9]+||' | sort -u >> $url/recon/httprobe/alive.txt

echo "[+] Checking for possible subdomain takeover..."
subzy run --targets $url/recon/final.txt --hide_fails >> $url/recon/potential_takeovers/potential_takeovers.txt

echo "[+] Scanning for open ports..."
nmap -Pn -iL $url/recon/httprobe/alive.txt -T4 -F -oA $url/recon/scans/scanned

# Ensure the nmap scan completes and the file is created
while [ ! -f "$url/recon/scans/scanned.gnmap" ]; do
    sleep 1
done

echo "[+] Highlighting interesting services and ports..."
mkdir -p $url/recon/scans/interesting
grep -iE "open.*(http|https|ssh|ftp|smtp|snmp|pop3|imap|rdp|telnet|ldap)" $url/recon/scans/scanned.gnmap > $url/recon/scans/interesting/interesting_ports.txt

# Use a smaller, more targeted username and password list
echo "[+] Creating targeted username and password lists..."
echo -e "admin\nroot\nuser\nsupport\nadministrator\ntest\nguest" > $url/recon/brutespray/usernames.txt
echo -e "admin\npassword\n123456\n1234\n12345\nadmin123\nguest\nguest123\nroot\nroot123\nadmin@123" > $url/recon/brutespray/passwords.txt

echo "[+] Running brutespray..."
brutespray -f $url/recon/scans/scanned.gnmap -u $url/recon/brutespray/usernames.txt -p $url/recon/brutespray/passwords.txt -t 5

# Check if brutespray ran successfully
if [ $? -ne 0 ]; then
    echo "[!] Brutespray encountered an error."
else
    echo "[+] Brutespray completed successfully."
fi

echo "[+] Scraping wayback data..."
cat $url/recon/final.txt | waybackurls >> $url/recon/wayback/wayback_output.txt
sort -u $url/recon/wayback/wayback_output.txt -o $url/recon/wayback/wayback_output.txt

echo "[+] Pulling and compiling all possible params found in wayback data..."
cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt
for line in $(cat $url/recon/wayback/params/wayback_params.txt); do
    echo $line'='
done

echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..."
for line in $(cat $url/recon/wayback/wayback_output.txt); do
    ext="${line##*.}"
    if [[ "$ext" == "js" ]]; then
        echo $line >> $url/recon/wayback/extensions/js1.txt
        sort -u $url/recon/wayback/extensions/js1.txt >> $url/recon/wayback/extensions/js.txt
    fi
    if [[ "$ext" == "html" ]]; then
        echo $line >> $url/recon/wayback/extensions/jsp1.txt
        sort -u $url/recon/wayback/extensions/jsp1.txt >> $url/recon/wayback/extensions/jsp.txt
    fi
    if [[ "$ext" == "json" ]]; then
        echo $line >> $url/recon/wayback/extensions/json1.txt
        sort -u $url/recon/wayback/extensions/json1.txt >> $url/recon/wayback/extensions/json.txt
    fi
    if [[ "$ext" == "php" ]]; then
        echo $line >> $url/recon/wayback/extensions/php1.txt
        sort -u $url/recon/wayback/extensions/php1.txt >> $url/recon/wayback/extensions/php.txt
    fi
    if [[ "$ext" == "aspx" ]]; then
        echo $line >> $url/recon/wayback/extensions/aspx1.txt
        sort -u $url/recon/wayback/extensions/aspx1.txt >> $url/recon/wayback/extensions/aspx.txt
    fi
done

rm $url/recon/wayback/extensions/js1.txt
rm $url/recon/wayback/extensions/jsp1.txt
rm $url/recon/wayback/extensions/json1.txt
rm $url/recon/wayback/extensions/php1.txt
rm $url/recon/wayback/extensions/aspx1.txt

echo "[+] Running gowitness against all compiled domains..."
gowitness file -f $url/recon/httprobe/alive.txt --threads 5 --delay 10 --screenshot-path $url/recon/gowitness

echo "[+] Running a Nikto scan..."
for domain in $(cat $url/recon/httprobe/alive.txt); do
    mkdir -p $url/recon/scans/vulnerabilities
    nikto -h $domain -output $url/recon/scans/vulnerabilities/${domain}_nikto.txt -Format txt -Tuning x 6 9
done

echo "[+] Spidering the website with gospider..."
for domain in $(cat $url/recon/httprobe/alive.txt); do
    gospider -s "http://$domain" -o $url/recon/spider -c 10 -d 1
done

echo "[+] Running ffuf for directory busting..."
for domain in $(cat $url/recon/httprobe/alive.txt); do
    ffuf -w /usr/share/wordlists/dirb/common.txt -u http://$domain/FUZZ -o $url/recon/ffuf/${domain}_ffuf.json
    jq -r '.results[] | "\(.url)\n"' $url/recon/ffuf/${domain}_ffuf.json >> $url/recon/ffuf/${domain}_ffuf_all.txt

    # Check if the found URLs are alive
    cat $url/recon/ffuf/${domain}_ffuf_all.txt | httprobe | tee $url/recon/ffuf/${domain}_ffuf_alive.txt
done

echo "[+] Formatting ffuf output for readability..."
for file in $url/recon/ffuf/*_ffuf_alive.txt; do
    sed -i 'G' "$file"
done

echo "[+] Running Nuclei scans with all available templates..."
nuclei -l $url/recon/httprobe/alive.txt -t ~/nuclei-templates/ -severity critical,high,medium -o $url/recon/nuclei/nuclei_results.txt

echo "[+] Highlighting interesting files and directories..."
grep -iE "admin|login|upload|db|backup|config" $url/recon/ffuf/*_ffuf_alive.txt > $url/recon/ffuf/interesting.txt

echo "[+] Performing reverse WHOIS lookup..."
whois $url > $url/recon/whois/${url}_whois.txt
if [ $? -eq 0 ]; then
    echo "[+] WHOIS lookup for $url completed successfully."
else
    echo "[!] WHOIS lookup for $url encountered an error."
fi

echo "[+] Performing ASN lookup for IPs..."
for ip in $(grep -oP '\d+\.\d+\.\d+\.\d+' $url/recon/scans/scanned.gnmap | sort -u); do
    asn_lookup $ip
done

echo "[+] Creating summary files..."

# Create a summary of critical vulnerabilities from Nuclei results
grep -iE "severity: Critical" $url/recon/nuclei/nuclei_results.txt > $url/recon/summaries/critical_vulnerabilities.txt

# Create a summary of high vulnerabilities from Nuclei results
grep -iE "severity: High" $url/recon/nuclei/nuclei_results.txt > $url/recon/summaries/high_vulnerabilities.txt

# Create a summary of interesting files and directories from FFUF results
cp $url/recon/ffuf/interesting.txt $url/recon/summaries/interesting_files_and_directories.txt

echo "[+] Creating a summary of interesting ports..."
{
    echo "Interesting Ports for $url"
    echo "========================="
    cat $url/recon/scans/interesting/interesting_ports.txt | while read -r line; do
        echo "$line"
        echo "-------------------------"
    done
} > $url/recon/summaries/interesting_ports.txt

echo "[+] Web Application Recon Complete, Happy Hacking!"
