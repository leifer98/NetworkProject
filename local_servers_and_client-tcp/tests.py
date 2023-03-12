import subprocess
import os
import client
import sys


def run_servers():
    print("starting all servers")
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    command = ["python", "multi-server_socket.py"]
    subprocess.Popen(command)
    command = ["python", "app_server.py"]
    subprocess.Popen(command)
    command = ["python", "DNS.py"]
    subprocess.Popen(command)
    command = ["python", "DHCP.py"]
    subprocess.Popen(command)


def run_client(domain):
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    command = ["python", "client.py", domain]
    subprocess.Popen(command)


def test1():
    run_servers()
    # run_client(domain="the_famous_cat.com")


if __name__ == "__main__":
    test1()
