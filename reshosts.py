#!/bin/python3

import sys
#import os
import subprocess
import threading
import platform
import socket
import argparse
import re
from datetime import date, datetime

alive_hosts = {}
dead_hosts = []

#Arguments handling
parser = argparse.ArgumentParser()

parser.add_argument('IP_ADDR') # Positional argument
parser.add_argument('-v', '--verbose', action='store_true', help="provide more detailed information during execution")
parser.add_argument('-m', '--ms', action='store_true', help="display ping times in milliseconds")

args = parser.parse_args()

def log(data):
    if args.verbose:
        print(data)


def get_ms(cmd):
    match = re.search(r'time[=<]([\d.]+)', cmd.stdout)
        
    if match:
        return match.group(1)

    return 'Unknown'


# Ping a targeted IP address
def ping(ip, operating_system):
    # Execute command for each thread depending on the operating system...
    if operating_system == 'Linux':
        try:
            # Linux command
            response = subprocess.run(['ping', '-c', '1', '-w', '5', ip], capture_output=True, text=True)
        except Exception as e:
            print(e)            

    else:
        try:
            # Windows command
            response = subprocess.run('ping -n 1 -w 5000 ' + ip + ' | find "TTL"', capture_output=True, text=True, shell=True)
        except Exception as e:
            print(e)

    log(f'Currently checking host {ip}')

    # Check if host is up
    if response.returncode == 0:
        ms = get_ms(response)
        alive_hosts[ip] = ms
        
        log(f'{ip} is up!')
    else:
        dead_hosts.append(ip)
        log(f'{ip} is down or unreachable!')


# Check if arg is in valid IP address format
def is_format_valid(arg):
    octets = arg.split('.')
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(-\d{1,3})?$'

    ranged_value = False # Set to true in the script if there is a range provided
    values_range = []

    if not re.match(ip_pattern, arg):
        return False
    
    for i, octet in enumerate(octets):
        if '-' in octet:
            if i != 3:
                return False

            start, end = map(int, octet.split('-'))
            if not(0 <= start <= end <= 255):
                return False
            
            values_range.extend([start, end])

            return values_range, True

        if not(0 <= int(octet) <= 255):
            return False
        
    return values_range, True



# Print error in the terminal
def error_arg():
    error = """The IP address you provided is not valid!
Please ensure that you follow this format: reshosts 192.168.1.0-100 (last octet only for ranges)"""

    print(error)


# Print the results from the scan
def results(total_hosts: str) -> str:
    result = "\nALIVE HOSTS:\n"
    
    # Fetch IP's hostname
    if alive_hosts:
        for host in alive_hosts.keys():
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except Exception as e:
                hostname = "Unknown host"

            # Format the result depending on args passed by the user
            result += f'{host}, {hostname}'
            if args.ms: result += f' ({alive_hosts[host]} ms)'
            result += '\n'
    else:
        result += 'None\n'

    # Print amount of dead hosts out of all the hosts checked
    total_dead_hosts = str(len(dead_hosts))
    result += f'\nDEAD HOSTS:\n{total_dead_hosts} out of {total_hosts}'
        
    return result 

        
if __name__ == '__main__':
    operating_system = platform.system()   
    threads_list = []
    supported_os = ['Windows', 'Linux']
    
    # Check if OS is supported
    if operating_system not in supported_os:
        print(f'Could not identify OS {operating_system}... Exiting')
        exit(1)
    
    # Check if positional argument is in IP address format
    if not is_format_valid(args.IP_ADDR):
        error_arg()
        exit(1)

    # Converting the IP address into a list
    ip = args.IP_ADDR.split('.')

    # Fetching the ranges from the last octet
    ranges = is_format_valid(args.IP_ADDR)[0]

    # Check if the IP is ranged (X.X.X.X-X)
    ip_is_ranged = True if len(ranges) > 1 else False

    # Getting the current date (Hour, Minute, Seconds and Day, Month, Year)
    current_time_date = datetime.now().strftime("%H:%M:%S") + " " + str(date.today())

    if ip_is_ranged:
        first_ip = ip[0] + '.' + ip[1] + '.' + ip[2] + '.' + str(ranges[0])
        last_ip = ip[0] + '.' + ip[1] + '.' + ip[2] + '.' + str(ranges[1])
        
        ip_info = f'from {first_ip} to {last_ip}'
    else:
        ip_info = f'on {args.IP_ADDR}'
    
    print(f'Starting reshosts {ip_info} at {current_time_date}')
    
    try:        
        # Start a thread for each IP address to ping
        for i in range(ranges[0], ranges[1]):
            host = f'{ip[0]}.{ip[1]}.{ip[2]}.{str(i)}'
            t = threading.Thread(target=ping, args=(host, operating_system))
            t.start()
            threads_list.append(t)

        # Very important to avoid showing results before every thread finishes its execution
        for t in threads_list:
            t.join()
    except Exception as e:
        ping(args.IP_ADDR, operating_system)
    
    # Print the results!
    total_check_hosts = str(ranges[1] - ranges[0]) if ip_is_ranged else "1"
    print(results(total_check_hosts))
