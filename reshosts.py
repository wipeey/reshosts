#!/bin/python3

import sys
import os
import threading
import platform

alive_hosts = []
dead_hosts = []


# Ping a targeted IP address
def ping(ip, operating_system):
    # Execute command for each thread depending on the operating system...
    if operating_system == 'Linux':
        response = os.system(f'ping -c 1 -w 5 {ip} > /dev/null 2>&1') # Lunix command
    else:
        response = os.system(f'ping -c 1 -w 5 {ip} | find "TTL" > nul') # Windows command
        
    # Check if host is up
    if response == 0:
        alive_hosts.append(ip)
    else:
        dead_hosts.append(ip)

        
# Check if arg is in valid IP address format
def is_ip_addr(arg):
    ip = arg.split('.')

    if len(ip) < 4:
        return False
    
    for octet in ip:
        if octet.isdigit():
            octet = int(octet)
        else:
            return False

        if octet >= 0 and octet <= 255:
            continue
        else:
            return False

    return True


# Print error in the terminal
def error_arg():
    error = """You must provide a valid network IP address!
(e.g: 192.168.1.0 ==> will sort through every IP between 192.168.1.0 to 192.168.1.255)\n
PLEASE note that the script will only ping through last octet...
    """

    print(error)

# Print the results from the scan
def results():
    result = "\nALIVE HOSTS:\n"
    
    # Handle proper syntax
    if alive_hosts:
        for host in alive_hosts:
            if alive_hosts.index(host) == len(alive_hosts)-1:
                result += f'{host}\n'
            else:
                result += f'{host}, '
    else:
        result += '0\n'
        
    result += f'\nDEAD HOSTS:\n{str(len(dead_hosts))}'
        
    print(result)

    
def main():   
    operating_system = platform.system()   
    threads_list = []
    supported_os = ['Windows', 'Linux']
    args = sys.argv
    
    # Check if OS is supported
    if operating_system not in supported_os:
        print(f'Could not identify OS {operating_system}... Exiting')
        exit(1)
    
    # Check if there are enough arguments
    if len(args) < 2:
        error_arg()
        exit(1)
    
    # Check if first argument is in IP address format
    if not is_ip_addr(args[1]):
        error_arg()
        exit(1)
    
    ip = args[1].split('.')
    
    # Start a thread for each IP address to ping
    for i in range(0, 255):
        host = f'{ip[0]}.{ip[1]}.{ip[2]}.{str(i)}'
        t = threading.Thread(target=ping, args=(host, operating_system))
        t.start()
        threads_list.append(t)
    
    print('Pinging...')
    
    # Very important to avoid showing results before every thread finishes its execution
    for t in threads_list:
        t.join()
    
    # Show the results!
    results()
    
    
if __name__ == '__main__':
    main()
