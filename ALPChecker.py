import os
import subprocess
import time
import shutil
import signal 
import sys

class SConnection:
    def __init__(self, ServerProcess, ConnectionPort, ClientCommunicationPort, ClientProcess):
        self.ServerProcess = ServerProcess
        self.ConnectionPort = ConnectionPort
        self.ClientCommunicationPort = ClientCommunicationPort
        self.ClientProcess = ClientProcess
        
    def __eq__(self, other):
        if (self.ServerProcess == other.ServerProcess and self.ConnectionPort == other.ConnectionPort and
            self.ClientCommunicationPort == other.ClientCommunicationPort and self.ClientProcess == other.ClientProcess):
            return True
        return False

def get_ser_ports(line):
    ll = line.split()
    ports = []
    ports.append(ll[2][2:])
    ports.append(ll[4].split('(')[0])
    return ports
    
def get_cl_ports(line):
    ll = line.split()
    ports = []
    ports.append(ll[0])
    ports.append(ll[3])
    if (ll[6].find('ffff') > -1):
        ports.append(ll[6])
    else:
        if(len(ll)>7):
            if (ll[7].find('ffff') > -1):
                ports.append(ll[7])
            else:
                ports.append('0')
        else:
            ports.append('0')
    return ports

def reading_error(proc, serverConnections):
    if (len(serverConnections) < 1):
        return serverConnections
    while(serverConnections[-1].ServerProcess == proc):
        serverConnections.pop()
        if (len(serverConnections) < 1):
            return serverConnections
    return serverConnections
    
    
def get_procs_adrs():
    outfile = open("file.txt", "w")
    errfile = open("err.txt", "w")
    livekd = subprocess.Popen("livekd", stdin=subprocess.PIPE, stdout=outfile, stderr=errfile, text=True)
    livekd.stdin.write("!dml_proc\n")
    time.sleep(5)
    livekd.kill()
    out, err = livekd.communicate()
    outfile.close()
    errfile.close()
  
def alpc_info(addrs):  
    outfile = open("file.txt", "w")
    errfile = open("err.txt", "w")
    livekd = subprocess.Popen("livekd", stdin=subprocess.PIPE, stdout=outfile, stderr=errfile, text=True)
    for addr in addrs:
        livekd.stdin.write("!alpc /lpp " + addr +"\n") 
    outfile.close()
    errfile.close()

def get_procs():
    outfile2 = open("file3.txt", "r")
    serverConnections = []
    clientConnections = []
    connectionPortAddrs = []
    connectionPortNames = []
    s = 0
    n = 0
    while True:
        line = outfile2.readline()
        if not line:
            break
        if (line.find('Error') > -1):
            serverConnections = reading_error(proc, serverConnections)
            s = 0
            continue
        if (line.find('ffff') == -1):
            continue
        if (line.find('not a connection port') > -1):
            continue
        if (s == 0 and not (line.startswith('Ports'))):
            continue
        if (line.startswith('Ports c')):
            s = 1
            n+=1
            proc = line.split()[5][:-1]
            continue

        if (line.startswith('Ports t')):
            s = 2
            continue
        if (s == 1):
            if (line.find('connections') > -1):
                ConPort = line.split('(')[0][1:]
                portName = line.split("'")[1]
                connectionPortAddrs.append(ConPort)
                connectionPortNames.append(portName)
                continue
            ports = get_ser_ports(line[2:])
            connection = SConnection(proc, ConPort, ports[0], ports[1])
            serverConnections.append(connection)
            continue
        if (s == 2):
            ports = get_cl_ports(line[1:])
            if (ports[2].find('ffff') > -1 and ports[1].find('ffff') > -1 and ports[0].find('ffff') > -1 and proc.find('ffff')>-1 and ports[2] != proc):
                connection = SConnection(ports[2], ports[1], ports[0], proc)
                clientConnections.append(connection)
    outfile2.close()
    return serverConnections, clientConnections, connectionPortAddrs, connectionPortNames, n

def CheckConnections(serverConnections, clientConnections):
    suspiciousConnections = []
    for clconnection in clientConnections:
        k = 0
        exists = 0
        for i in range(len(serverConnections)):
            if(serverConnections[i].ServerProcess == clconnection.ServerProcess):
                exists = 1
                if (clconnection == serverConnections[i]):
                    k+=1
            else:
                if exists == 1:
                    break
        
        if (k!=1 and exists == 1):
            suspiciousConnections.append(clconnection)
    return suspiciousConnections
         
def read_addr_file(filename):
    addrs = []
    pids = []
    names = []
    fd = open(filename, "r")
    while True:
        line = fd.readline()
        if not line:
            break
        if line.startswith('ffff'):
            l = line.split()
            if (len(l)<3):
                continue
            if ( l[2] == 'livekd64.exe' or l[2] == 'kd.exe'):
                os.kill(int(l[1], 16), signal.SIGTERM)
            else:
                addrs.append(l[0])
                pids.append(l[1])
                names.append(l[2])
    fd.close() 
    return addrs, pids, names
            
get_procs_adrs()
time.sleep(15)
shutil.copyfile('file.txt', 'file2.txt')
addrs, pids, names = read_addr_file("file2.txt")
if (len(addrs) < 5):
    print("Sorry, error in getting process occured. Try again.")
    sys.exit(0)
alpc_info(addrs) 
time.sleep(600)   
shutil.copyfile('file.txt', 'file3.txt')

serverConnections, clientConnections, connectionPortAddrs, connectionPortNames, n = get_procs()
if len(serverConnections)< 10:
    print("System errors occured while program was running, please, try again")
    sys.exit(0)
if n < len(addrs)-3:
    print("Did not manage to read all the alpc information. Please, try again")
    sys.exit(0)
suspiciousConnections = CheckConnections(serverConnections, clientConnections)
if (len(suspiciousConnections)==0):
    print("No problems detected")
else:
    print("Suspicious connections found:")
    for connection in suspiciousConnections:
        cconnection = connection.ClientProcess[:8] + "`" + connection.ClientProcess[8:]
        i = addrs.index(cconnection)
        sconnection = connection.ServerProcess[:8] + "`" + connection.ServerProcess[8:]
        j = addrs.index(sconnection)
        try:
            k = connectionPortAddrs.index(connection.ConnectionPort)
            name = connectionPortNames[k]
        except:
            k = -1
        if (names[i] == 'svchost.exe' or names[j] == 'svchost.exe'):
            print("Service connection: ")
        print("Client process: " + names[i] + " with pid: " + pids[i] + " with address: " + connection.ClientProcess + " and ClientCommunicationPort: " + connection.ClientCommunicationPort)
        print("Server process: " + names[j] + " with pid " + pids[j] + " with address: " + connection.ServerProcess)
        if (k > -1):
            print("ConnectionPort: " + connectionPortNames[k] + " with address: " + connection.ConnectionPort + "\n")
        else:
            print("ConnectionPort with address: " + connection.ConnectionPort + " was defined by system as not a connection port\n")

