# WebAppRecon
A modified version of the Web Application Reconnaissance Automation script from the Practical Ethical Hacker course by TCM Security. 

I found that amass rather than taking forever, wouldn't scan properly to begin with. I changed the amass command in the script, switched from subjack to subzy for the subdomain takeover section as subjack is deprecated. I also added in installations for all of the dependencies for the script to run. 

### Installation Instructions

```
git clone https://github.com/N0vaSky/WebAppRecon
```
```
cd WebAppRecon
chmod +x webrecon.sh
sudo ./webrecon.sh <domain>
```


### Happy Hacking!


[Side note: If you're running this on Kali, it's probably a good idea to run pimpmykali by Dewalt first to avoid any other unforseen issues. Just use the "N" option when you run pimpmykali for a "new vm setup". Ref: https://github.com/Dewalt-arch/pimpmykali]

