# Web Reconnaissance Script

This repository hosts `webrecon.sh`, a web reconnaissance script that builds upon the original script from TCM Security's Practical Ethical Hacking course, created by Heath Adams. This script has been enhanced to improve functionality, automate dependencies, and increase usability for comprehensive security assessments. 

## Features

- **Automated Dependency Management**: Automates the installation of necessary tools, ensuring all dependencies are met without manual intervention.
- **Advanced Subdomain Enumeration**: Leverages `assetfinder` and `amass` for robust subdomain discovery.
- **Subdomain Takeover Analysis**: Utilizes `subzy` to check for potential subdomain takeovers.
- **Comprehensive Port and Vulnerability Scanning**: Includes tools like `nmap` and `nikto` for detailed scanning.
- **Visual Reconnaissance**: Employs `gowitness` for capturing screenshots of live web pages.
- **Brute Force Testing**: Uses `brutespray` for automated brute force attacks on discovered services.
- **Historical Data Analysis**: Utilizes `waybackurls` for collecting historical URL data.
- **Extended Web Scraping and Analysis**: Integrates `gospider` and `ffuf` for deep web crawling and directory busting.

### Happy Hacking!

[Side note: It's probably a good idea to run pimpmykali by Dewalt first to avoid any other unforseen issues. Just use the "N" option when you run pimpmykali for a "new vm setup". Ref: https://github.com/Dewalt-arch/pimpmykali]

Here is the original script by TCM Security that was built upon in this version: https://pastebin.com/MhE6zXVt

## Installation

Clone the repository and navigate to the directory where the script is located:

```bash
git clone https://github.com/N0vaSky/WebAppRecon.git
cd WebAppRecon
sudo ./webrecond.sh
