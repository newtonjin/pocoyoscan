# POCOYO SCANNER
Python vulnerability scanner with a few tools


<pre>
 ██▓███  ▒█████  ▄████▄  ▒█████▓██   ██▓▒█████       ██████ ▄████▄  ▄▄▄      ███▄    █ ███▄    █▓█████ ██▀███  
▓██░  ██▒██▒  ██▒██▀ ▀█ ▒██▒  ██▒██  ██▒██▒  ██▒   ▒██    ▒▒██▀ ▀█ ▒████▄    ██ ▀█   █ ██ ▀█   █▓█   ▀▓██ ▒ ██▒
▓██░ ██▓▒██░  ██▒▓█    ▄▒██░  ██▒▒██ ██▒██░  ██▒   ░ ▓██▄  ▒▓█    ▄▒██  ▀█▄ ▓██  ▀█ ██▓██  ▀█ ██▒███  ▓██ ░▄█ ▒
▒██▄█▓▒ ▒██   ██▒▓▓▄ ▄██▒██   ██░░ ▐██▓▒██   ██░     ▒   ██▒▓▓▄ ▄██░██▄▄▄▄██▓██▒  ▐▌██▓██▒  ▐▌██▒▓█  ▄▒██▀▀█▄  
▒██▒ ░  ░ ████▓▒▒ ▓███▀ ░ ████▓▒░░ ██▒▓░ ████▓▒░   ▒██████▒▒ ▓███▀ ░▓█   ▓██▒██░   ▓██▒██░   ▓██░▒████░██▓ ▒██▒
▒▓▒░ ░  ░ ▒░▒░▒░░ ░▒ ▒  ░ ▒░▒░▒░  ██▒▒▒░ ▒░▒░▒░    ▒ ▒▓▒ ▒ ░ ░▒ ▒  ░▒▒   ▓▒█░ ▒░   ▒ ▒░ ▒░   ▒ ▒░░ ▒░ ░ ▒▓ ░▒▓░
░▒ ░      ░ ▒ ▒░  ░  ▒    ░ ▒ ▒░▓██ ░▒░  ░ ▒ ▒░    ░ ░▒  ░ ░ ░  ▒    ▒   ▒▒ ░ ░░   ░ ▒░ ░░   ░ ▒░░ ░  ░ ░▒ ░ ▒░
░░      ░ ░ ░ ▒ ░       ░ ░ ░ ▒ ▒ ▒ ░░ ░ ░ ░ ▒     ░  ░  ░ ░         ░   ▒     ░   ░ ░   ░   ░ ░   ░    ░░   ░ 
            ░ ░ ░ ░         ░ ░ ░ ░        ░ ░           ░ ░ ░           ░  ░        ░         ░   ░  ░  ░     v1
                ░               ░ ░                        ░                                                   
  by: Newtonj1n
</pre>

# Requirements
nmap</br>
psutil</br>
json</br>
Python3</br>


# Arguments
It's a tool that you can use primally in any OS for pentester and vulnerabilities search, also search for exploits for any host that you scan</br>
You will have a few options in the first menu as:</br>
Search Exploit : Search for open services in a host and search exploits based on the versions and the services ports</br>
Show all hosts alive in local network : Uses the ethernet adapters to find any other hosts that you can reach</br>
Wordpress Scan : Vulnerable Paths scan, Nmap scan and also WPScan in the same place with the results on the findinds</br>
Show all remote TCP connections: Previously it was possible even to send a Reverse Shell to the connection PID, but i removed that option for now, only shows all the connections established in your computer</br>
Set WPScan API token, needded if you also need to WPScan in the url you are using</br>


# Att
I'm constantly adding and removing options, because sometimes i feel like it... Looks like if a made it too easy it will be a way much OP (I don't want that). 
>Actual status : Working in a CVE/Exploit correlation in the search exploit option, it's already working, but i'm thinking if it's really something that should be on in the github.


![image](https://user-images.githubusercontent.com/42048980/236964674-6d52edeb-b8d1-43cd-b404-0188cced693a.png)
