import subprocess
import os
import client
import sys


def run_servers():
    print("starting all servers")
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    command = ["python3", "multi-server_socket.py"]
    subprocess.Popen(command)
    command = ["python3", "app_server.py"]
    subprocess.Popen(command)
    command = ["python3", "DNS.py"]
    subprocess.Popen(command)
    command = ["python3", "DHCP.py"]
    subprocess.Popen(command)


def run_client(domain):
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    command = ["python3", "client.py", domain]
    subprocess.Popen(command)


def test1():
    run_servers()
    run_client(domain="the_famous_cat.com")


if __name__ == "__main__":
    test1()
