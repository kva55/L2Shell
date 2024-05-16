import os

def selectInterface():
    # This is for displaying the interfaces on windows
    if os.name == "nt":
        from scapy.arch import get_windows_if_list
        print("[*] OS Detection as NT.\tUsing get_windows_if_list")
        print("[*] Displaying all the interfaces, please select the interface by specifying the \"guid\"")
        interfaces = get_windows_if_list()
        interfacelist = []
        for iface_info in interfaces:
            print("-----------------------------------------")
            print("Interface name:", iface_info["name"])
            print("Interface description:", iface_info["description"])
            print("IP addresses:", iface_info["ips"])
            print("MAC address:", iface_info["mac"])
            print("GUID:", iface_info["guid"])
            interfacelist.append(iface_info["guid"]) # This adds all the available interfaces into a list
        print("-----------------------------------------")
        
        userin = input("Interface> ")
        if userin in interfacelist:
            print("[+] Interface exists.")
            return userin
        else:
            print("[-] Interface unavailable")
            return ""
    
    # This is for displaying the interfaces on linux
    elif os.name == "posix":
        from scapy.all import conf
        print("[*] OS Detection as POSIX.\tUsing conf.ifaces")
        print("[*] Displaying all the interfaces, please select the interface by specifying the \"interface name\"")
        interfaces = conf.ifaces
        interfacelist = []
        for iface_name, iface_info in interfaces.items():
            print("-----------------------------------------")
            print("Interface name:", iface_name)
            print("IP addresses:", iface_info.ip)
            print("Description:", iface_info.description)
            print("MAC address:", iface_info.mac)
            interfacelist.append(iface_name) # This adds all the available interfaces into a list
        print("-----------------------------------------")
        
        userin = input("Interface> ")
        if userin in interfacelist:
            print("[+] Interface exists.")
            return userin
        else:
            print("[-] Interface unavailable")
            return ""