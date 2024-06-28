#!/bin/python3

import sys
import os
import threading
import platform
import socket
import argparse

alive_hosts = []
dead_hosts = []

#Arguments handling
parser = argparse.ArgumentParser()

parser.add_argument('IP_ADDR') # Positional argument
parser.add_argument('-v', '--verbose', action='store_true')

args = parser.parse_args()

def log(data):
    if args.verbose:
        print(data)


# Ping a targeted IP address
def ping(ip, operating_system):
    # Execute command for each thread depending on the operating system...
    if operating_system == 'Linux':
        response = os.system(f'ping -c 1 -w 5 {ip} > /dev/null 2>&1') # Linux command
    else:
        response = os.system(f'ping -c 1 -w 5 {ip} | find "TTL" > nul') # Windows command

    log(f'Currently checking host {ip}')

    # Check if host is up
    if response == 0:
        alive_hosts.append(ip)
        log(f'{ip} is up!')
    else:
        dead_hosts.append(ip)
        log(f'{ip} is down or unreachable!')


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
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except Exception as e:
                hostname = "Unknown host"

            result += f'{host}, {hostname}\n'
    else:
        result += 'None\n'
        
    result += f'\nDEAD HOSTS:\n{str(len(dead_hosts))}'
        
    print(result)

    
def main():
    operating_system = platform.system()   
    threads_list = []
    supported_os = ['Windows', 'Linux']
    
    # Check if OS is supported
    if operating_system not in supported_os:
        print(f'Could not identify OS {operating_system}... Exiting')
        exit(1)
    
    # Check if positional argument is in IP address format
    if not is_ip_addr(args.IP_ADDR):
        error_arg()
        exit(1)
    
    ip = args.IP_ADDR.split('.')
    
    # Start a thread for each IP address to ping
    for i in range(0, 255):
        host = f'{ip[0]}.{ip[1]}.{ip[2]}.{str(i)}'
        t = threading.Thread(target=ping, args=(host, operating_system))
        t.start()
        threads_list.append(t)

    # Very important to avoid showing results before every thread finishes its execution
    for t in threads_list:
        t.join()
    
    # Show the results!
    results()
    
    
if __name__ == '__main__':
    main()
