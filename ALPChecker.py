import os
import subprocess
import time
import psutil
import shutil
import signal 
import sys

class ConnectPort:
    def __init__(self, Name, Message_Queue, connections, proc):
        self.Name = Name
        self.Message_Queue = Message_Queue
        self.connections = connections
        self.process = proc

class Attacked:
    def __init__(self, ServerProcess, ConnectionPort, OtherConnectionPort, ClientCommunicationPort, ClientProcess):
        self.ServerProcess = ServerProcess
        self.ConnectionPort = ConnectionPort
        self.OtherConnectionPort = OtherConnectionPort
        self.ClientCommunicationPort = ClientCommunicationPort
        self.ClientProcess = ClientProcess

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
    try:
        ports.append(ll[4].split('(')[0])
    except:
        ports.append(' ')
    return ports
    
def get_cl_ports(line):
    ll = line.split()
    ports = []
    if (len(ll)<6):
        return ports
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
    connectionPorts = []
    detectedAttacks = []
    s = 0
    n = 0
    while True:
        line = outfile2.readline()
        if not line:
            break
        if (line.find('points to wrong')> -1):
            s = 3
            otherConnectionPort = line.split()[-1]
            continue
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
        if ( s == 3):
            ports = get_ser_ports(line[2:])
            if (ports[-1]!= ' '):
                attack = Attacked(proc, ConPort, otherConnectionPort, ports[0], ports[1])
                detectedAttacks.append(attack)
            else:
                print("Careful! System can be attacked. Check the suspicious connections")
            s = 1
            continue
        if (s == 1):
            if (line.find('connections') > -1):
                ConPort = line.split('(')[0][1:]
                portName = line.split("'")[1]
                portcomps = line.split()
                connectionPortAddrs.append(ConPort)
                CPort = ConnectPort(portName, portcomps[-3][:-1], portcomps[-2], proc)
                connectionPorts.append(CPort)
                continue
            ports = get_ser_ports(line[2:])
            connection = SConnection(proc, ConPort, ports[0], ports[1])
            serverConnections.append(connection)
            continue
        if (s == 2):
            ports = get_cl_ports(line[1:])
            if (len(ports)<3):
                continue
            if (ports[2].find('ffff') > -1 and ports[1].find('ffff') > -1 and ports[0].find('ffff') > -1 and proc.find('ffff')>-1 and ports[2] != proc):
                connection = SConnection(ports[2], ports[1], ports[0], proc)
                clientConnections.append(connection)
    outfile2.close()
    return detectedAttacks, serverConnections, clientConnections, connectionPortAddrs, connectionPorts, n

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

detectedAttacks, serverConnections, clientConnections, connectionPortAddrs, connectionPorts, n = get_procs()
if len(serverConnections)< 10:
    print("System errors occured while program was running, please, try again")
    sys.exit(0)
#if n < len(addrs)-3:
#    print("Did not manage to read all the alpc information. Please, try again")
#    sys.exit(0)
suspiciousConnections = CheckConnections(serverConnections, clientConnections)
if (len(detectedAttacks)>0):
    print("Attention! Attack detected!")
    for attack in detectedAttacks:
        cconnection = attack.ClientProcess[:8] + "`" + attack.ClientProcess[8:]
        i = addrs.index(cconnection)
        sconnection = attack.ServerProcess[:8] + "`" + attack.ServerProcess[8:]
        j = addrs.index(sconnection)
        pid = pids[i]
        try:
            username = psutil.Process(int(pid, 16)).username()
            cmdline = psutil.Process(int(pid, 16)).cmdline()
        except:
            username = ' '
            cmdline = ' '
        try:
            k1 = connectionPortAddrs.index(attack.ConnectionPort)
        except:
            k1 = -1
        try:
            k2 = connectionPortAddrs.index(attack.ConnectionPort)
        except:
            k2 = -1
        print("Server process ", names[j], " with pid ", pids[j], " with address ", attack.ServerProcess, " is not connected correctly")
        print("To client process ", names[i], " with pid ", pids[i], " with address ", attack.ClientProcess)
        #print("The client is now connected to Connection Port ", attack.OtherConnectionPort)
        if (username == ' '):
            print("Client process no longer exists")
        else:
            print("Client process belongs to user ", username, ", path: ", cmdline)
        if (k1 > -1):
            print("The client was connected to ConnectionPort: " + connectionPorts[k1].Name + " with address: " + attack.ConnectionPort)
            #print("This Connection Port has " + connectionPorts[k].Message_Queue + " messages in a queue and " + connectionPorts[k].connections + " active connections" )
            if (connectionPorts[k1].connections!='0'):
                print("Active connections of the ", attack.ConnectionPort, ":")
                m = 0
                for s in serverConnections:
                    if (s.ConnectionPort == attack.ConnectionPort):
                        m+=1
                        print(s.ClientProcess, " via Client Communication Port ", s.ClientCommunicationPort)
                        if (m>=int(connectionPorts[k1].connections)):
                            break
        else:
            print("ConnectionPort with address: " + attack.ConnectionPort + " was defined by system as not a connection port\n")
        if (k2 > -1):
            print("Now the client seems to be connected to the Connection Port ", connectionPorts[k2].Name, " with address: ", attack.OtherConnectionPort)
            nconnection = connectionPorts[k2].process[:8] + "`" + connectionPorts[k2].process[8:]
            j = addrs.index(nconnection)
            print("that actually belongs to the server process ", names[j], " with address ", connectionPorts[k2].process)
            if (connectionPorts[k2].connections!='0'):
                print("Active connections of the ", attack.OtherConnectionPort, ":")
                m = 0
                for s in serverConnections:
                    if (s.ConnectionPort == attack.OtherConnectionPort):
                        m+=1
                        print(s.ClientProcess, " via Client Communication Port ", s.ClientCommunicationPort)
                        if (m>=int(connectionPorts[k2].connections)):
                            break
        else:
            print("ConnectionPort with address: " + attack.OtherConnectionPort + " was defined by system as not a connection port\n")
        print()
        
if (len(suspiciousConnections)==0 and len(detectedAttacks)==0):
    print("No problems detected")
else:
    print("Suspicious connections found:")
    for connection in suspiciousConnections:
        cconnection = connection.ClientProcess[:8] + "`" + connection.ClientProcess[8:]
        i = addrs.index(cconnection)
        sconnection = connection.ServerProcess[:8] + "`" + connection.ServerProcess[8:]
        j = addrs.index(sconnection)
        pid = pids[i]
        try:
            username = psutil.Process(int(pid, 16)).username()
            cmdline = psutil.Process(int(pid, 16)).cmdline()
        except:
            username = ' '
            cmdline = ' '
        try:
            k = connectionPortAddrs.index(connection.ConnectionPort)
        except:
            k = -1
        if (names[i] == 'svchost.exe' or names[j] == 'svchost.exe'):
            print("Service connection: ")
        print("Client process: " + names[i] + " with pid: " + pids[i] + " with address: " + connection.ClientProcess + " and ClientCommunicationPort: " + connection.ClientCommunicationPort)
        if (username == ' '):
            print("Client process no longer exists")
        else:
            print("Client process belongs to user ", username, ", path: ", cmdline)
        print("Server process: " + names[j] + " with pid " + pids[j] + " with address: " + connection.ServerProcess)
        if (k > -1):
            print("ConnectionPort: " + connectionPorts[k].Name + " with address: " + connection.ConnectionPort)
            print("This Connection Port has " + connectionPorts[k].Message_Queue + " messages in a queue and " + connectionPorts[k].connections + " active connections" )
            if (connectionPorts[k].connections!='0'):
                print("Active connections of the ", connection.ConnectionPort, ":")
                m = 0
                for s in serverConnections:
                    if (s.ConnectionPort == connection.ConnectionPort):
                        m+=1
                        print(s.ClientProcess, " via Client Communication Port ", s.ClientCommunicationPort)
                        if (m>=int(connectionPorts[k].connections)):
                            break
        else:
            print("ConnectionPort with address: " + connection.ConnectionPort + " was defined by system as not a connection port\n")
        print()

