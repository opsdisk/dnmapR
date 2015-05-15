#! /usr/bin/env python
# dnmapR_client.py is a revised and updated version of dnmap_client.py
# GPL v3
# Opsdisk LLC | opsdisk.com 

# dnmap version modified: .6 
# http://sourceforge.net/projects/dnmap

# Copyright (C) 2009  Sebastian Garcia
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#
# Author:
# Sebastian Garcia eldraco@gmail.com
#
# Based on code from Twisted examples.
# Copyright (c) Twisted Matrix Laboratories.

# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

import argparse
import os
import random
import shlex
import sys
import time
from subprocess import Popen
from subprocess import PIPE

# openssl check
try:
    from OpenSSL import SSL
except:
    print '[-] Python openssl library required: apt-get install python-openssl'
    exit(-1)
    
# twisted check
try:
    from twisted.internet.protocol import ClientFactory, ReconnectingClientFactory
    from twisted.protocols.basic import LineReceiver
    from twisted.internet import ssl, reactor
except:
    print '[-] Python twisted library required: apt-get install python-twisted'
    exit(-1)
    
vernum = '1.0'

def check_clean(line):
    global debug
    try:
        outboundChars = [';', '#', '`']
        ret = True
        for char in outboundChars:
            if char in line:
                ret = False
        return ret
        
    except Exception as inst:
        print '[-] Problem in dataReceived function'
        print type(inst)
        print inst.args
        print inst
        
        
class NmapClient(LineReceiver):
    def connectionMade(self):
        global clientID
        global alias
        global debug
        
        print '[+] Client connected succesfully...waiting for more commands.'
        if debug:
            print '[+] Your client ID is: {0}, and your alias is: {1}'.format(str(clientID), str(alias))
            
        euid = os.geteuid()
        
        # Do not send the euid, just tell if we are root or not.
        if euid == 0:
            # True
            iamroot = 1
        else:
            # False
            iamroot = 0
            
        # 'Client ID' text must be sent to receive another command
        line = 'Starts the Client ID:{0}:Alias:{1}:Version:{2}:ImRoot:{3}'.format(str(clientID), str(alias), vernum, iamroot)
        if debug:
            print '[*] Line sent: {0}'.format(line)
        self.sendLine(line)
        
        #line = 'Send more commands to Client ID:{0}:Alias:{1}:\0'.format(str(clientID), str(alias))
        line = 'Send more commands'
        if debug:
            print '[*] Line sent: {0}'.format(line)
        self.sendLine(line)
        
    def dataReceived(self, line):
        global debug
        global clientID
        global alias
        
        # If a wait is received, just wait.
        if 'Wait' in line:
            sleeptime = int(line.split(':')[1])
            time.sleep(sleeptime)

            # Ask for more
            #line = 'Send more commands to Client ID:{0}:Alias:{1}:'.format(str(clientID),str(alias))
            line = 'Send more commands'
            if debug:
                print '[*] Line sent: {0}'.format(line)
            self.sendLine(line)
        else:
        # dataReceived does not wait for end of lines, CR, or LF
            if debug:
                print "\tCommand Received: {0}".format(line.strip('\n').strip('\r'))
        
            # A little bit of protection from the server
            if check_clean(line):
                # Store the nmap output file so we can send it to the server later
                try:
                    nmapOutputFile = line.split('-oA ')[1].split(' ')[0].strip(' ')
                except IndexError:
                    randomFileName = str(random.randrange(0, 100000000, 1))
                    print '[-] No -oA argument, adding it to keep results. Added -oA ' + randomFileName
                    line = line + '-oA ' + randomFileName
                    nmapOutputFile = line.split('-oA ')[1].split(' ')[0].strip(' ')
                    
                try:
                    nameReturnCode = -1
                    
                    # Check for rate commands
                    # Verify that the server is NOT trying to force us to be faster. NMAP PARAMETER DEPENDENCE
                    if 'min-rate' in line:
                        tempVect = shlex.split(line)
                        wordIndex = tempVect.index('--min-rate')
                        # Just delete the --min-rate parameter with its value
                        nmapCommand = tempVect[0:wordIndex] + tempVect[wordIndex + 1:]
                    else:
                        nmapCommand = shlex.split(line)
                        
                    # Do we have to add a max-rate parameter?
                    '''if maxRate:
                        nmapCommand.append('--max-rate')
                        nmapCommand.append(str((maxRate)))'''
                        
                    # Strip the command, so we can control that only nmap is really executed 
                    nmapCommand = nmapCommand[1:]
                    nmapCommand.insert(0, 'nmap')
                    
                    # Recreate the final command and display it
                    nmapCommandString = ''
                    for i in nmapCommand:
                        nmapCommandString = nmapCommandString + i + ' '
                    print "\tExecuted command: {0}".format(nmapCommandString)
                    
                    nmapProcess = Popen(nmapCommand, stdout=PIPE)
                    rawNmapOutput = nmapProcess.communicate()[0]
                    nameReturnCode = nmapProcess.returncode
                    
                except OSError:
                    print '[-] nmap is not installed: apt-get install nmap'
                    exit(-1)
                    
                except ValueError:
                    rawNmapOutput = '[-] Invalid nmap arguments.'
                    print rawNmapOutput
                    
                except Exception as inst:
                    print '[-] Problem in dataReceived function'
                    print type(inst)
                    print inst.args
                    print inst
                    
                if nameReturnCode >= 0:
                    # nmap ended ok
                    
                    # Tell the server that we are sending the nmap output
                    print '\tSending output to the server...'
                    #line = 'Nmap Output File:{0}:{1}:{2}:'.format(nmapOutputFile.strip('\n').strip('\r'),str(clientID),str(alias))
                    line = 'nmap output file:{0}:'.format(nmapOutputFile.strip('\n').strip('\r'))
                    if debug:
                        print '[*] Line sent: {0}'.format(line)
                    self.sendLine(line)
                    self.sendLine(rawNmapOutput)
                    #line = 'Nmap Output Finished:{0}:{1}:{2}:'.format(nmapOutputFile.strip('\n').strip('\r'),str(clientID),str(alias))
                    line = 'nmap output finished:{0}:'.format(nmapOutputFile.strip('\n').strip('\r'))
                    if debug:
                        print '[*] Line sent: {0}'.format(line)
                    self.sendLine(line)
                    
                    # Move nmap output files to it's directory
                    os.system('mv *.nmap nmap_output > /dev/null 2>&1')
                    os.system('mv *.gnmap nmap_output > /dev/null 2>&1')
                    os.system('mv *.xml nmap_output > /dev/null 2>&1')
                    
                    # Ask for another command.
                    # 'Client ID' text must be sent to receive another command
                    print '[*] Waiting for more commands...'
                    #line = 'Send more commands to Client ID:{0}:Alias:{1}:'.format(str(clientID),str(alias))
                    line = 'Send more commands'
                    if debug:
                        print '[*] Line sent: {0}'.format(line)
                    self.sendLine(line)
           
            else:
                # Unknown command sent to client
                print '[!] Unknown command sent to this client: {0}'.format(line)
                line = 'Send more commands'
                if debug:
                    print '[*] Line sent: {0}'.format(line)
                self.sendLine(line)
                
                
class NmapClientFactory(ReconnectingClientFactory):
    try:
        protocol = NmapClient
        
        def startedConnecting(self, connector):
            print '[+] Attempting connection to server'
            
        def clientConnectionFailed(self, connector, reason):
            print '[-] Connection failed: ', reason.getErrorMessage()
            # Try to reconnect
            print '[*] Trying to reconnect. Please wait...'
            ReconnectingClientFactory.clientConnectionLost(self, connector, reason)
            
        def clientConnectionLost(self, connector, reason):
            print '[-] Connection lost. Reason: {0}'.format(reason.getErrorMessage())
            # Try to reconnect
            print '[*] Trying to reconnect in 10 secs. Please wait...'
            ReconnectingClientFactory.clientConnectionLost(self, connector, reason)
    
    except Exception as inst:
        print '[-] Problem in NmapClientFactory'
        print type(inst)
        print inst.args
        print inst
        
        
def process_commands():
    global serverIP
    global serverPort
    global clientID
    global factory
    
    try:
        print '[+] Client started...'
        
        # Generate a unique client ID
        clientID = str(random.randrange(0, 100000000, 1))
        
        # Create the output directory
        print '[*] Nmap output files stored in \'nmap_output\' directory...'
        if not os.path.exists('./nmap_output'):
            os.system('mkdir nmap_output > /dev/null 2>&1')
        
        factory = NmapClientFactory()
        # Do not wait more that 10 seconds between re-connections
        factory.maxDelay = 10
        
        reactor.connectSSL(str(serverIP), int(serverPort), factory, ssl.ClientContextFactory())
        reactor.run()
        
    except Exception as inst:
        print '[-] Problem in process_commands function'
        print type(inst)
        print inst.args
        print inst
        
        
def network_port_type(data):
    if int(data) >= 0 and int(data) <= 65535:
        return int(data)
    else:
        raise argparse.ArgumentTypeError("{} is not a valid TCP port".format(data))
        
def main():
    global serverIP
    global serverPort
    global alias
    global debug
    #global maxRate
    
    parser = argparse.ArgumentParser(description='dnmapR_client version ' + vernum)
    parser.add_argument('-s', dest='serverip', action='store', default='127.0.0.1', help='Server IP to connect to. Default is 127.0.0.1')
    parser.add_argument('-p', dest='serverport', action='store', default=46001, type=network_port_type, help='Server port to connect to. Default is 46001.')
    parser.add_argument('-a', dest='alias', action='store', default='anonymous', help='Alias for this client.')
    #parser.add_argument('-m', dest='maxrate', action='store', default=10000, help='Force dnmapR_client to use at most this rate. Useful to slow nmap down. Adds the --max-rate parameter.')
    parser.add_argument('-d', dest='debug', action='store_true', default=False, help='Debugging')
   
    args = parser.parse_args()
    
    serverIP = args.serverip
    serverPort = args.serverport
    alias = args.alias.strip('\n').strip('\r').strip(' ')
    #maxRate = args.maxrate
    debug = args.debug
    
    try:
        # Start connecting
        process_commands()
        
    except KeyboardInterrupt:
        # Handle CTRL-C interrupt.
        print "[!] Keyboard interrupt detected...exiting."
        sys.exit(1)
        
if __name__ == '__main__':
    main()
