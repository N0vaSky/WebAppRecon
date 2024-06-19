# Web Reconnaissance Script

This repository hosts `webrecon.sh`, a web reconnaissance script that builds upon the original script from TCM Security's Practical Ethical Hacking course, created by Heath Adams. This script has been enhanced to improve functionality, automate dependencies, and increase usability for comprehensive security assessments. 

## Features

- **Automated Dependency Management**: Automates the installation of necessary tools, ensuring all dependencies are met without manual intervention.
- **Subdomain Enumeration**: Leverages `assetfinder` and `amass` for robust subdomain discovery.
- **Probing for live pages**: Uses `httprobe` and creates a file of all the alive pages to be scanned. 
- **Subdomain Takeover Analysis**: Utilizes `subzy` to check for potential subdomain takeovers.
- **Comprehensive Port and Vulnerability Scanning**: Includes tools like `nmap`, `nikto`, and `nuclei` for detailed scanning.
- **Visual Reconnaissance**: Employs `gowitness` for capturing screenshots of live web pages.
- **Brute Force Testing**: Uses `brutespray` for automated brute force attacks on discovered services found via `nmap`.
- **Historical Data Analysis**: Utilizes `waybackurls` for collecting historical URL data.
- **Extended Web Scraping and Analysis**: Integrates `gospider` and `ffuf` for deep web crawling and directory busting.
- **Reverse WHOIS lookup and associated ASN numbers**: Performs a whois lookup and grabs the associated ASN numbers for the discovered IP's.

### Happy Hacking!

[Side note: It's probably a good idea to run pimpmykali by Dewalt first to avoid any other unforseen issues. Just use the "N" option when you run pimpmykali for a "new vm setup". Ref: https://github.com/Dewalt-arch/pimpmykali]

Here is the original script by TCM Security that was built upon in this version: https://pastebin.com/MhE6zXVt

## Installation

Clone the repository and navigate to the directory where the script is located:

```bash
git clone https://github.com/N0vaSky/WebAppRecon.git
cd WebAppRecon
sudo ./webrecond.sh
