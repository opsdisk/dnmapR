**This project is no longer maintained.  See Scantron for a distributed nmap/masscan framework (<https://github.com/rackerlabs/scantron>)**

# dnmapR
dnmap revised (dnmapR) is a modernized and enhanced version of dnmap

For security processionals and penetration testers that want to distribute nmap scans to different clients, Seb Garcia created a great tool called [dnmap](http://sourceforge.net/projects/dnmap), short for distributed nmap.  There are two main parts to dnmap.  The first is the server component, which hosts the commands that clients run.  The second part consists of the clients, which connect to the server to pull nmap tasks.  More detailed overviews of dnmap can be found here:

* [http://mateslab.weebly.com/dnmap-the-distributed-nmap.html](http://mateslab.weebly.com/dnmap-the-distributed-nmap.html)

* [http://www.tripwire.com/state-of-security/vulnerability-management/distributed-nmap-port-scanning-dnmap-megacluster/](http://www.tripwire.com/state-of-security/vulnerability-management/distributed-nmap-port-scanning-dnmap-megacluster/)

I started looking at the code and got an itch to modernize and enhance it, hence [dnmapR](https://github.com/opsdisk/dnmapR).  The core functionality and dnmap protocol has not been changed. The current improvements include:

* All command-line arguments are read in using Python's `argparse` library, which replaces the deprecated `optparse`.

* Removal of unused variables and lines of code, in addition to enhancing the conformity with the [PEP-8 Style Guide for Python Code](https://www.python.org/dev/peps/pep-0008/) with respect to variable names, functions, spaces, and overall readability.

* Moved default server log location to the directory running dnmapR_server.py

* Added Linux command-line pastable to assist in generating your own PEM file:
```bash
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out server.pem;cat key.pem >> server.pem; rm -f key.pm
```

* Added a switch (-i) to specify the server interface to listen on, with the default being 127.0.0.1.  I wanted the ability to leverage SSH tunnels for the client and server to communicate.  Using SSH tunnels reduces open ports on the server and firewall management.  For example, say you ran dnmapR\_server.py on a local Linux box, and wanted to run dnmapR_client.py on two different Virtual Private Servers.  The commands would look like:

```bash
# Terminal 1 - Server.
python dnmapR_server.py -f commands.txt -i 127.0.0.1 -p 46001 -P server.pem 
   
# Terminal 2 - Client 1. Connect to VPS1, and setup an SSH tunnel that redirects all traffic hitting 127.0.0.1:46001 on VPS1 to the server on 127.0.0.1:46001
ssh user@vps1 -R 46001:127.0.0.1:46001

# Instruct the client to connect on 127.0.0.1:46001 to utilize the SSH tunnel
python dnmapR_client.py -s 127.0.0.1 -p 46001 -a vps1

# Terminal 3 - Client 2. Connect to VPS2, and setup an SSH tunnel that redirects all traffic hitting 127.0.0.1:46001 on VPS2 to the server on 127.0.0.1:46001
ssh user@vps2 -R 46001:127.0.0.1:46001

# Instruct the client to connect on 127.0.0.1:46001 to utilize the SSH tunnel
python dnmapR_client.py -s 127.0.0.1 -p 46001 -a vps2
```

This allows the client and server to communicate through an SSH connection.  If you do not use SSH tunnels, the communication between the server and client is still encrypted using an updated [PEM](http://en.wikipedia.org/wiki/Privacy-enhanced_Electronic_Mail) certificate.

The TODO list includes:

* Add maxrate switch back into the code.  
* Fold in [@sixdub's](https://twitter.com/sixdub) Django web front-end code called [Minions](https://github.com/sixdub/Minions) 
* Avoid writing dnmapR_clients.py results to disk

The code can be found here: [https://github.com/opsdisk/dnmapR](https://github.com/opsdisk/dnmapR)

Comments, suggestions, and improvements are always welcome. Be sure to follow [@opsdisk](https://twitter.com/opsdisk) on Twitter for the latest updates.
 
