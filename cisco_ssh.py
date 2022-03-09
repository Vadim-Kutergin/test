try:
    import paramiko    
except ImportError:
    raise ImportError("Please install \"paramiko\" module: pip install paramiko")
import time
import socket
import argparse

def ssh_command(ip,username,password,commands,enable='', config_mode=False, read_all=False,max_bytes=60000,short_pause=0.5,long_pause=1,timeout=3):
    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cl.connect(hostname=ip,username=username,password=password,look_for_keys=False,allow_agent=False,timeout=1)
    with cl.invoke_shell() as ssh:
        if enable!='':
            ssh.send("enable\n")
            ssh.send(f"{enable}\n")
            time.sleep(short_pause)
        if config_mode:
            commands = ['conf t']+commands+['end']
        if read_all:
            commands = ['terminal length 0','conf t']+commands
        for command in commands:
            ssh.send(command+'\n')
            time.sleep(short_pause)
        
        if config_mode:
            ssh.send('wr\n')
            time.sleep(long_pause)
        
        output = ""
        while True:
            try:
                part = ssh.recv(max_bytes).decode("utf-8")
                output += part
                if not read_all:
                    break
                time.sleep(0.5)
            except socket.timeout:
                break
    cl.close()
    return output
        
   

def ssh_command_wr(ip,username,password,commands,enable='',read_all=False ,max_bytes=600000,short_pause=0.5,long_pause=1,timeout=3):
    return ssh_command(ip,username,password,commands,enable='', config_mode=True,read_all=read_all,max_bytes=60000,short_pause=0.5,long_pause=1,timeout=3)


'''
if __name__ == "__main__"


    parser = argparse.ArgumentParser(description="Send commands to SSH terminal.")
    
    parser.add_argument("-u", dest="username",  help="SSH username.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-r",metavar='Range', dest="range", help="IP range. E. 192.168.1.1-192.168.2.1 or 192.168.1.1-5")
    group.add_argument("-n",metavar='Network', dest="network", help="IP network. E. 192.168.1.0/24")
    group.add_argument('-a',metavar='Host', dest="hosts",nargs='*', help='Host or hosts lst. E. 192.168.1.0 192.168.1.2')
    group.add_argument('-f',metavar='File', help='Hosts lst  from file.')

    parser.add_argument('command file',metavar='commands')
    parser.add_argument("-w", action='store_true', help="add coonf t/wr commands")
    args = parser.parse_args()
'''
