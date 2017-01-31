#! /usr/bin/env python
# dnmapR_server.py is a revised and updated version of dnmap_server.py
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
import datetime
import logging
import logging.handlers
import os
import sys
import time

# openssl check
try:
    from OpenSSL import SSL
except:
    print '[-] Python openssl library required: apt-get install python-openssl'
    exit(-1)
    
# twisted check
try:
    from twisted.internet.protocol import Factory, Protocol
    from twisted.internet import ssl, reactor, task
    from twisted.python import log
    from twisted.python.logfile import DailyLogFile
except:
    print '[-] Python twisted library required: '
    print 'apt-get install python-twisted-bin python-twisted-core'
    exit(-1)
    
    
# Global variables
vernum = '1.0'
nmapCommandsFile = ''
nmapCommand = []
fileDescriptor = ''
traceFile = ''
nmapOutputComingBack = False
outputFileDescriptor = ''
filePosition = 0
clients = {}

# This is to assure that the first time we run, something is shown
temp = datetime.datetime.now()
delta = datetime.timedelta(seconds=5)
lastShowTime = temp - delta

def timeout_idle_clients():
    """
    This function search for idle clients and mark them as offline, so we do not display them
    """
    global mlog
    global verboseLevel
    global clients
    global clientTimeout
    try:
        for clientID in clients:
            now = datetime.datetime.now()
            timeDiff = now - clients[clientID]['LastTime']
            if timeDiff.seconds >= clientTimeout:
                clients[clientID]['Status'] = 'Offline'
                
    except Exception as inst:
        if verboseLevel > 2:
            msgline = '[-] Problem in mark_as_idle function'
            mlog.error(msgline)
            print msgline
            msgline = type(inst)
            mlog.error(msgline)
            print msgline
            msgline = inst.args
            mlog.error(msgline)
            print msgline
            msgline = inst
            mlog.error(msgline)
            print msgline
            
            
def read_file_and_fill_nmap_variable():
    """
    Here we fill the nmapCommand with the lines of the txt file. Only the first time. Later this file should be filled automatically
    """
    global nmapCommandsFile
    global nmapCommand
    global fileDescriptor
    global traceFile
    global filePosition
    global mlog
    global verboseLevel

    if not fileDescriptor:
        fileDescriptor = open(nmapCommandsFile, 'r')

    lastLine = ''
    traceFile = nmapCommandsFile + '.dnmaptrace'

    try:
        size = os.stat(traceFile).st_size
        traceFileDescriptor = open(traceFile,'r')
        if size > 0:
            # We already have a trace file. We must be reading the same original file again after some running...
            traceFileDescriptor.seek(0)
            lastLine = traceFileDescriptor.readline()
            
            # Search for the line stored in the trace file
            # This allow us to CTRL-C the server and reload it again without having to worry about were where we reading commends.
            otherline = fileDescriptor.readline()
            while otherline:
                if lastLine == otherline:
                    break
                otherline = fileDescriptor.readline()
        traceFileDescriptor.close()

    except OSError:
        pass

    # Do we have some more lines added since last time?
    if filePosition != 0:
        # If we are called again, and the file was already read. Close the file so we can 'see' the new commands added
        # and then continue from the last previous line...
        fileDescriptor.flush()
        fileDescriptor.close()
        fileDescriptor = open(nmapCommandsFile, 'r')

        # Go forward until what we read last time
        fileDescriptor.seek(filePosition)

    line = fileDescriptor.readline()
    filePosition = fileDescriptor.tell()
    linesRead = 0
    while line:
        # Avoid lines with # so we can comment on them
        if not '#' in line:
            nmapCommand.insert(0,line)
        line = fileDescriptor.readline()
        filePosition = fileDescriptor.tell()
        linesRead += 1
    
    msgline = 'Command lines read: {0}'.format(linesRead)
    mlog.debug(msgline)
    
    
class ServerContextFactory:
    global mlog
    global verboseLevel
    global pemfile
    # Copyright (c) Twisted Matrix Laboratories.
    """ Only to set up SSL """
    def getContext(self):
        """
        Create an SSL context.
        This is a sample implementation that loads a certificate from a file 
        called 'server.pem'.
        """
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        try:
            ctx.use_certificate_file(pemfile)
            ctx.use_privatekey_file(pemfile)
        except:
            print '[-] You need to have a PEM file for the server to work. If it is not in your same directory, just point to it with -P switch'
        return ctx
        
        
def show_info():
    global verboseLevel
    global mlog
    global clients
    global lastShowTime
    global startTime
    global sortType

    try:
        now = datetime.datetime.now()
        diffTime = now - startTime

        amount = 0
        for j in clients:
            if clients[j]['Status'] != 'Offline':
                amount += 1

        if verboseLevel > 0:
            line = '=| MET:{0} | Online clients: {1} |='.format(diffTime, amount)
            print line
            mlog.info(line)
            
        if clients != {}:
            if verboseLevel > 1:
                line = 'Clients connected'
                print line
                mlog.info(line)
                line = '-----------------'
                print line
                mlog.info(line)
                #line = 'Alias\t#Commands\tLast Time Seen\t\t\tVersion\tIsRoot\tStatus'
                line = '{0:15}\t{1}\t{2}\t{3}\t{4}\t\t{5}\t{6}\t{7}\t{8}\t{9}'.format('Alias', '#Commands', 'Last Time Seen', '(time ago)', 'UpTime', 'Version', 'IsRoot', 'RunCmdXMin', 'AvrCmdXMin', 'Status')
                print line
                mlog.info(line)
                for i in clients:
                    if clients[i]['Status'] != 'Offline':
                        # Strip the name of the day and the year
                        temp = clients[i]['LastTime'].ctime().split(' ')[1:-1]
                        lasttime = ''
                        for j in temp:
                            lasttime = lasttime + str(j) + ' '

                        timeDiff = datetime.datetime.now() - clients[i]['LastTime']
                        timeDiffSecs = int( (timeDiff.seconds + (timeDiff.microseconds / 1000000.0) ) % 60)
                        timeDiffMins = int(  (timeDiff.seconds + (timeDiff.microseconds / 1000000.0) ) / 60)
                        uptimeDiff = datetime.datetime.now() - clients[i]['FirstTime']
                        uptimeDiffHours = int( (uptimeDiff.seconds + (uptimeDiff.microseconds / 1000000.0)) / 3600)
                        uptimeDiffMins = int( ((uptimeDiff.seconds % 3600) + (uptimeDiff.microseconds / 1000000.0)) / 60)
                        
                        line = '{0:15}\t{1}\t\t{2}({3:2d}\'{4:2d}\")\t{5:2d}h{6:2d}m\t\t{7}\t{8}\t{9:10.1f}\t{10:9.1f}\t{11}'.format(clients[i]['Alias'], clients[i]['NbrCommands'], lasttime, timeDiffMins, timeDiffSecs, uptimeDiffHours, uptimeDiffMins , clients[i]['Version'], clients[i]['IsRoot'], clients[i]['RunCmdsxMin'], clients[i]['AvrCmdsxMin'], clients[i]['Status'])
                        print line
                        mlog.info(line)
                        
            print
            lastShowTime = datetime.datetime.now()
            
    except Exception as inst:
        if verboseLevel > 2:
            msgline = '[-] Problem in show_info function'
            mlog.error(msgline)
            print msgline
            msgline = type(inst)
            mlog.error(msgline)
            print msgline
            msgline = inst.args
            mlog.error(msgline)
            print msgline
            msgline = inst
            mlog.error(msgline)
            print msgline
    
def send_one_more_command(ourtransport, clientID):
    # Extract the next command to send.
    global nmapCommand
    global verboseLevel
    global mlog
    global clients
    
    try:
        alias = clients[clientID]['Alias']
        commandToSend = nmapCommand.pop()
        
        line = '[*] Data sent to client ID ' + clientID + ' (' + alias + ')'
        log.msg(line, logLevel=logging.INFO)
        if verboseLevel > 2:
            print line
        line = '\t' + commandToSend.strip('\n')
        log.msg(line, logLevel=logging.INFO)
        if verboseLevel > 2:
            print line
        ourtransport.transport.write(commandToSend)
        clients[clientID]['NbrCommands'] += 1
        clients[clientID]['LastCommand'] = commandToSend
        clients[clientID]['Status'] = 'Executing'
        
    except IndexError:
        # If the list of commands is empty, look for new commands
        line = '[*] No more commands in queue.'
        log.msg(line, logLevel=logging.DEBUG)
        if verboseLevel > 2:
            print line
        line = '\tMaking the client ' + str(clientID) + ' (' + str(alias) + ')' + ' wait 10 secs for new commands to arrive...'
        log.msg(line, logLevel=logging.DEBUG)
        if verboseLevel > 2:
            print line
        ourtransport.transport.write('Wait:10')
        
    except Exception as inst:
        print '[-] Problem in Send More Commands'
        print type(inst)
        print inst.args
        print inst

def process_input_line(data, ourtransport, clientID):
    global mlog
    global verboseLevel
    global clients
    global traceFile
    global nmapCommand
    global nmapOutputComingBack
    global outputFileDescriptor

    try:
        # What to do. Send another command or store the nmap output?
        if 'Starts the Client ID:' in data:
            # No more nmap lines coming back
            if nmapOutputComingBack:
                nmapOutputComingBack = False

            alias = data.split(':')[3].strip('\n').strip('\r').strip(' ')
            try:
                clientVersion = data.split(':')[5].strip('\n').strip('\r').strip(' ')
                clientIsRoot = 'False' if data.split(':')[7].strip('\n').strip('\r').strip(' ') == 0 else 'True'
            except IndexError:
                # It is an old version and it is not sending these data
                clientVersion = '0.1?'
                clientIsRoot = '?'

            try:
                # Do we have it yet?
                # Yes
                value = clients[clientID]['Alias']
            except KeyError:
                # No
                clients[clientID] = {}
                clients[clientID]['Alias'] = alias
                clients[clientID]['FirstTime'] = datetime.datetime.now()
                clients[clientID]['LastTime'] = datetime.datetime.now()
                clients[clientID]['NbrCommands'] = 0
                clients[clientID]['Status'] = 'Online'
                clients[clientID]['LastCommand'] = ''
                clients[clientID]['Version'] = clientVersion
                clients[clientID]['IsRoot'] = clientIsRoot
                clients[clientID]['RunCmdsxMin'] = 0
                clients[clientID]['AvrCmdsxMin'] = 0

            msgline = '[+] Client ID connected: {0} ({1})'.format(str(clientID), str(alias))
            log.msg(msgline, logLevel=logging.INFO)
            if verboseLevel > 1:
                print msgline

        elif 'Send more commands' in data:
            alias = clients[clientID]['Alias']
            
            clients[clientID]['Status'] = 'Online'
            nowtime = datetime.datetime.now()
            clients[clientID]['LastTime'] = nowtime

            # No more nmap lines coming back
            if nmapOutputComingBack:
                nmapOutputComingBack = False

            send_one_more_command(ourtransport, clientID)

        elif 'nmap output file' in data and not nmapOutputComingBack:
            # Nmap output start to come back...
            nmapOutputComingBack = True
            
            alias = clients[clientID]['Alias']
            
            clients[clientID]['Status'] = 'Online'
            
            # Compute the commands per hour
            # 1 more command. Time is between lasttimeseen and now
            timeSinceCmdStart = datetime.datetime.now() - clients[clientID]['LastTime']
            
            # Cumulative average
            prevCa = clients[clientID]['AvrCmdsxMin']
            clients[clientID]['RunCmdsxMin'] =  60 / (timeSinceCmdStart.seconds + ( timeSinceCmdStart.microseconds / 1000000.0))
            clients[clientID]['AvrCmdsxMin'] = ( clients[clientID]['RunCmdsxMin'] + (clients[clientID]['NbrCommands'] * prevCa) ) / ( clients[clientID]['NbrCommands'] + 1 )
            
            # update the LastTime
            nowtime = datetime.datetime.now()
            clients[clientID]['LastTime'] = nowtime
            
            # Create the dir
            if not os.path.exists('./nmap_results'):
                os.system('mkdir nmap_results > /dev/null 2>&1')
            
            # Get the output file from the data
            # We strip \n. 
            nmapOutputFile = 'nmap_results/' + data.split(':')[1].strip('\n') + '.nmap'
            if verboseLevel > 2:
                log.msg('\tNmap output file is: {0}'.format(nmapOutputFile), logLevel=logging.DEBUG)
                
            outputFileDescriptor = open(nmapOutputFile, 'a+')
            outputFileDescriptor.writelines('Client ID:' + clientID + ':Alias:' + alias)
            outputFileDescriptor.flush()
            
        elif 'nmap output finished' not in data and nmapOutputComingBack:
            # Store the output to a file.
            alias = clients[clientID]['Alias']

            clients[clientID]['Status'] = 'Storing'
            nowtime = datetime.datetime.now()
            clients[clientID]['LastTime'] = nowtime

            log.msg('\tStoring nmap output for client {0} ({1}).'.format(clientID, alias), logLevel=logging.DEBUG)
            outputFileDescriptor.writelines(data + '\n')
            outputFileDescriptor.flush()
         
        elif 'nmap output finished' in data and nmapOutputComingBack:
            # Nmap output finished
            nmapOutputComingBack = False

            alias = clients[clientID]['Alias']

            clients[clientID]['Status'] = 'Online'
            nowtime = datetime.datetime.now()
            clients[clientID]['LastTime'] = nowtime
        
            # Store the finished nmap command in the file, so we can retrieve it if needed later.
            finishedNmapCommand = clients[clientID]['LastCommand']
            traceFileDescriptor = open(traceFile, 'w')
            traceFileDescriptor.seek(0)
            traceFileDescriptor.writelines(finishedNmapCommand)
            traceFileDescriptor.flush()
            traceFileDescriptor.close()
            
            if verboseLevel > 2:
                print '[*] Storing command {0} in trace file.'.format(finishedNmapCommand.strip('\n').strip('\r'))
                
            outputFileDescriptor.close()
            
    except Exception as inst:
        print '[-] Problem in process_input_line'
        print type(inst)
        print inst.args
        print inst
        
        
class NmapServerProtocol(Protocol):
    """ This is the function that communicates with the client """
    global mlog
    global verboseLevel
    global clients
    global nmapCommand
    global mlog

    def connectionMade(self):
        if verboseLevel > 0:
            pass
            
    def connectionLost(self, reason):
        peerHost = self.transport.getPeer().host
        peerPort = str(self.transport.getPeer().port)
        clientID = peerHost + ':' + peerPort
        alias = clients[clientID]['Alias']
        
        if verboseLevel > 1:
            msgline = '[-] Connection lost in the protocol. Reason:{0}'.format(reason)
            msgline2 = '[-] Connection lost for {0} ({1}).'.format(alias, clientID)
            log.msg(msgline, logLevel=logging.DEBUG)
            print msgline2
            
            clients[clientID]['Status'] = 'Offline'
            commandToRedo = clients[clientID]['LastCommand']
            if commandToRedo != '':
                nmapCommand.append(commandToRedo)
            if verboseLevel > 2:
                print '[*] Re-inserting command: {0}'.format(commandToRedo)
                
    def dataReceived(self, newdata):
        #global clientID
        
        data = newdata.strip('\r').strip('\n').split('\r\n')
        
        peerHost = self.transport.getPeer().host
        peerPort = str(self.transport.getPeer().port)
        clientID = peerHost + ':' + peerPort

        # If you need to debug
        if verboseLevel > 2:
            log.msg('Data received', logLevel=logging.DEBUG)
            log.msg(data, logLevel=logging.DEBUG)
            print '[*] Data received: {0}'.format(data)
            
        for line in data:
            process_input_line(line,self, clientID)
            
            
def process_nmap_commands(loggerName):
    """ Main function. Here we set up the environment, factory, interface, and port """
    global nmapCommandsFile
    global nmapCommand
    global port
    global mlog
    global verboseLevel
    global clientTimeout
    
    observer = log.PythonLoggingObserver(loggerName)
    observer.start()
    
    # Create the factory
    factory = Factory()
    factory.protocol = NmapServerProtocol
    
    # Create the time based print
    loop = task.LoopingCall(show_info)
    loop.start(5.0) # call every second
    
    # Create the time based file read
    loop2 = task.LoopingCall(read_file_and_fill_nmap_variable)
    loop2.start(30.0) # call every second
    
    # To mark idle clients as hold
    loop3 = task.LoopingCall(timeout_idle_clients)
    loop3.start(clientTimeout) # call every second
    
    # Create the reactor
    reactor.listenSSL(port, factory, ServerContextFactory(), interface=interface)
    reactor.run()
    
def network_port_type(data):
    if int(data) >= 0 and int(data) <= 65535:
        return int(data)
    else:
        raise argparse.ArgumentTypeError("{} is not a valid TCP port".format(data))
        
def main():
    global nmapCommandsFile
    global port
    global interface
    global logFile
    global logLevel
    global mlog
    global verboseLevel
    global startTime
    global clientTimeout
    global sortType
    global pemfile

    startTime = datetime.datetime.now()

    parser = argparse.ArgumentParser(description='dnmapR_server version ' + vernum, epilog = "dnmapR_server uses a \'<nmap-commands-file-name>.dnmaptrace\' file to know where it must continue reading the nmap commands file. If you want to start over again, just delete the \'<nmap-commands-file-name>.dnmaptrace\' file")
    parser.add_argument('-f', dest='nmapcommandsfile', action='store', help='nmap commands file')
    parser.add_argument('-p', dest='port', action='store', default=46001, type=network_port_type, help='TCP port where we listen for connections. Default is 46001')
    parser.add_argument('-i', dest='interface', action='store', default='127.0.0.1', help='Interface to listen on. Default is 127.0.0.1')
    parser.add_argument('-P', dest='pemfile', action='store', default='server.pem', help='PEM file to use for SSL connection. Default is server.pem. To generate your own: openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out server.pem;cat key.pem >> server.pem; rm -f key.pm')
    parser.add_argument('-L', dest='logfile', action='store', default='./dnmapR_server.log', help='Specify log file location. Default is ./dnmapR_server.log')
    parser.add_argument('-l', dest='loglevel', action='store', default='info', help='Log level. Defaults to info.')
    parser.add_argument('-v', dest='verboselevel', action='store', type=int, default=1, help='Verbosity level. Give a number between 1 and 5. Defaults to 1. Level 0 is quiet.')
    parser.add_argument('-t', dest='clienttimeout', action='store', type=int, default=3600, help='Number of seconds before classifying a client as offline. Default is 3600 (1 hour)')
    parser.add_argument('-s', dest='sorttype', default='Status', help='Field to sort the statical value. You can choose from: Alias, #Commands, UpTime, RunCmdXMin, AvrCmdXMin, Status')
    
    args = parser.parse_args()
    
    nmapCommandsFile = args.nmapcommandsfile
    port = args.port
    interface = args.interface
    pemfile = args.pemfile
    logFile = args.logfile
    logLevel = args.loglevel
    verboseLevel = args.verboselevel
    clientTimeout = args.clienttimeout
    sortType = args.sorttype

    if not nmapCommandsFile or not os.path.exists(nmapCommandsFile):
        print "[-] Specify a valid nmap command file (-f)"
        sys.exit(-1)
    if not os.path.exists(pemfile):
        print "[-] Specify a valid pem file, file " + pemfile + " does not exist. To generate your own:"
        print "openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out server.pem;cat key.pem >> server.pem; rm -f key.pem"
        sys.exit(-1)
    if not ( 0 <= verboseLevel <= 5 ):
        print "[-] Invalid verbosity level. Must be 0-5."
        sys.exit(-1)
    if not ( 0 <= clientTimeout ):
        print "[-] Invalid client timeout. Must be greater than 0."
        sys.exit(-1)
    
    print "[*] dnmapR_server version " + vernum 
    print "[*] Listening for connections on: " + interface + ":" + str(port)
    print "[*] Log file location: " + logFile
    
    try:
        # Set up logger
        # Set up a specific logger with our desired output level
        loggerName = 'MyLogger'
        mlog = logging.getLogger(loggerName)

        # Set up the log level
        numericLevel = getattr(logging, logLevel.upper(), None)
        if not isinstance(numericLevel, int):
            raise ValueError('[-] Invalid log level: %s' % loglevel)
        mlog.setLevel(numericLevel)
        
        # Add the log message handler to the logger
        handler = logging.handlers.RotatingFileHandler(logFile, backupCount=5)
        
        formater = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formater)
        mlog.addHandler(handler)
        # End logger
        
        # Fill the variable from the file
        read_file_and_fill_nmap_variable()
        
        # Start processing clients
        process_nmap_commands(loggerName)
        
    except KeyboardInterrupt:
        # Handle CTRL-C interrupt.
        print "[!] Keyboard interrupt detected...exiting."
        sys.exit(1)
        
if __name__ == '__main__':
    main()
