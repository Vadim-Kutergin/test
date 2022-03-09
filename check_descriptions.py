#!/usr/bin/env python

import sys
import ipaddress
import argparse
try:
    from pysnmp import hlapi
except ImportError:
    raise ImportError("Please install \"pysnmp\" module: pip install pysnmp")

try:
    from tabulate import tabulate
except ImportError:
    raise ImportError("Please install \"tabulate\" module: pip install tabulate")
try:
    from colorama import init, Fore, Back, Style
except ImportError:
    raise ImportError("Please install \"colorama\" module: pip install colorama")
import difflib

try:
    import paramiko    
except ImportError:
    raise ImportError("Please install \"paramiko\" module: pip install paramiko")
import time
import socket
import getpass

def read_file(filename):
    hosts=[]
    with open(filename,"r") as f:
        for line in f:
            line= line.rstrip('\n')
            hosts.append(line.split(';')[0])
        f.close()
    return hosts

def replace_all(text, dic):
    for i, j in dic.items():
        text = text.replace(i, j)
    return text

def colorize_difs(s1,s2,color=Fore.MAGENTA, skip_threshold=30):
    if len(s2)==0: return s2
    style= Style.RESET_ALL
    result=''
    c=0
    for s in difflib.ndiff(s1, s2):
        if s[0]=='-': continue
        elif s[0]==' ':
            c+=1
            new_style=Style.RESET_ALL
        else:
            new_style=color
        result += s[-1] if style==new_style else new_style+s[-1]
        style=new_style
    if 100*c/len(s2) >=skip_threshold:
        return result+Style.RESET_ALL
    return s2

def ip_range(range_str):
    ips= range_str.split('-')
    s_ip1,s_ip2=ips[0],ips[-1]
    if not '.' in s_ip2:
        s_ip2='.'.join(s_ip1.split('.')[:3]+[s_ip2])

    ip1=int(ipaddress.IPv4Address(s_ip1))
    ip2=int(ipaddress.IPv4Address(s_ip2))

    if ip1>ip2:
        ip1,ip2=ip2,ip1
    return [str(ipaddress.IPv4Address(i)) for i in range(ip1,ip2+1)]



def snmp_get(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData(),timeout=2,retries=0):
    handler = hlapi.getCmd(
        engine,
        credentials,
        hlapi.UdpTransportTarget((target, port),timeout, retries=0),
        context,
        *construct_object_types(oids)
    )
    return fetch(handler, 1)[0]

def construct_object_types(list_of_oids):
    object_types = []
    for oid in list_of_oids:
        object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
    return object_types

def fetch(handler, count):
    result = []
    for i in range(count):
        try:
            error_indication, error_status, error_index, var_binds = next(handler)
            if not error_indication and not error_status:
                items = {}
                for var_bind in var_binds:
                    items[str(var_bind[0])] = cast(var_bind[1])
                result.append(items)
            else:
                raise RuntimeError('Got SNMP error: {0}'.format(error_indication))
        except StopIteration:
            break
    return result

def fetch_auto(handler):
    result = []
    for (error_indication, error_status, error_index, var_binds) in handler:
        if not error_indication and not error_status:
            items = {}
            for var_bind in var_binds:
                items[str(var_bind[0])] = cast(var_bind[1])
            result.append(items)
        else:
            raise RuntimeError('Got SNMP error: {0}'.format(error_indication))
    return result

def cast(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        try:
            return float(value)
        except (ValueError, TypeError):
            try:
                return str(value)
            except (ValueError, TypeError):
                pass
    return value

def snmp_get_bulk(target, oids, credentials, count, start_from=0, port=161,
             engine=hlapi.SnmpEngine(), context=hlapi.ContextData(),timeout=2,retries=0):
    handler = hlapi.bulkCmd(
        engine,
        credentials,
        hlapi.UdpTransportTarget((target, port),timeout,retries),
        context,
        start_from, count,
        *construct_object_types(oids)
    )
    return fetch(handler, count)

def snmp_get_bulk_auto(target, oids, credentials, count_oid, start_from=0, port=161,
                  engine=hlapi.SnmpEngine(), context=hlapi.ContextData(),timeout=2,retries=0):
    count = snmp_get(target, [count_oid], credentials, port, engine, context)[count_oid]
    return snmp_get_bulk(target, oids, credentials, count, start_from, port, engine, context,timeout,retries)




def snmp_walk(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData(),timeout=2,retries=0):
    handler= hlapi.nextCmd(engine, credentials, hlapi.UdpTransportTarget((target, port),timeout,retries), context,
        *construct_object_types(oids),lexicographicMode=False)
    return fetch_auto(handler)


def cisco_ssh_command_wr(ip,username,password,commands,enable='' ,max_bytes=60000,short_pause=0.5,long_pause=1,timeout=3):
    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cl.connect(hostname=ip,username=username,password=password,look_for_keys=False,allow_agent=False,timeout=timeout)
    with cl.invoke_shell() as ssh:
        if enable!='':
            ssh.send("enable\n")
            ssh.send(f"{enable}\n")
            time.sleep(short_pause)
        commands = ['conf t']+commands+['end']
        #commands = ['terminal length 0','conf t']+commands+['end']
        for command in commands:
            ssh.send(command+'\n')
            time.sleep(short_pause)
        
        ssh.send('wr\n')
        time.sleep(long_pause)
        
        return ssh.recv(max_bytes).decode("utf-8")




sysName ='1.3.6.1.2.1.1.5.0'
ifNumber ='1.3.6.1.2.1.2.1.0'
ifIndex ='1.3.6.1.2.1.2.2.1.1'
ifDescr ='1.3.6.1.2.1.2.2.1.2'#.x = STRING: "FastEthernet0/0"
ifxName ='1.3.6.1.2.1.31.1.1.1.1'#.x = STRING: "Fa0/0"
ifxAlias ='1.3.6.1.2.1.31.1.1.1.18'#.x = STRING: "link to Router-Gi4"

cdpCacheDeviceId ='1.3.6.1.4.1.9.9.23.1.2.1.1.6'#.x.n = STRING: "R2"
cdpCacheDevicePort ='1.3.6.1.4.1.9.9.23.1.2.1.1.7'#.x.n = STRING: "FastEthernet0/0"
cdpCacheCapabilities ='1.3.6.1.4.1.9.9.23.1.2.1.1.9'#.x.n = Hex-STRING: 00 00 00 01

ifc_short_names ={'GigabitEthernet':'Gi','FastEthernet': 'Fa','TenGi': 'Te',}
short_names ={'.si.rt.ru':''}

#host ='10.142.126.4'
#comm='[htyfDfv'
user_name =""
password =''

def get_table(host,comm):
#    print (host)
    
    neighbors= snmp_walk(host, [cdpCacheDeviceId,cdpCacheDevicePort,cdpCacheCapabilities],hlapi.CommunityData(comm))
    interfaces = snmp_get_bulk_auto(host, [ifIndex,ifxName, ifxAlias], hlapi.CommunityData(comm), ifNumber)
    
#    print(neighbors)

    ifc_list=[]
    for i in interfaces:
        ifc_list.append(list(i.values()))

    neig_dict = get_ANE_neig_dict(neighbors)

    for k,v in neig_dict.items():
        neig_dict[k][0]=replace_all(v[0],short_names)
        neig_dict[k][1]=replace_all(v[1],ifc_short_names)


    tbl=[]
    for i in ifc_list:
        ifid=str(i[0])
        if ifid in neig_dict:
            rec=neig_dict.get(ifid)
            canonic= 'ane_{0}_{1}'.format(rec[0],rec[1])
            if i[2]!=canonic:
                tbl.append([i[1],rec[0],rec[1],i[2],canonic])

    return tbl

def get_ANE_neig_dict(neighbors):
    neig_dict={}
    for i in neighbors:
        l=list(i.values())
        k=list(i.keys())
        #print(l[0], int.from_bytes(str.encode(l[2]),"big"))
        if int.from_bytes(str.encode(l[2]),"big")&0x9 :#если это роутер или свитч
            neig_dict[k[0].split('.')[14]]=l#    добавляем с ключом =ifIndex
    return neig_dict

def get_name(host, comm):
    name=snmp_get(host, [sysName], hlapi.CommunityData(comm))[sysName]
    return name


def main(host,comm,colorize,interactive):
    try:
        name = get_name(host, comm)
        mismatch_tbl= get_table(host,comm)
    except RuntimeError as err:
        print (f'{host}',err)
        return


    if mismatch_tbl==[]:
        if interactive:
            print (f'checking {name} ({host}).. [Ok]')
        return
        

    if interactive:
        interact(host, colorize, name, mismatch_tbl)
    else:
        print('\nDescripton mismatch found on {0} ({1})'.format(replace_all(name,short_names),host))
        if colorize:
            for i in range(len(mismatch_tbl)):
                mismatch_tbl[i][4]= colorize_difs(mismatch_tbl[i][3],mismatch_tbl[i][4])
        print(tabulate(mismatch_tbl,['Local Port','Devace Name','Remote Port','Local Description','Expected']))
        print ('\n')



def interact(host, colorize, name, tbl):
    global user_name
    global password

    if user_name=='':
        print('Entering interactive mode. You`ll be asked about action with each found mismatch separately.')
        user_name=input('Enter your credentials:\nSSH username:')
        password=getpass.getpass(prompt='SSH password:')
    print('\n\nDescripton mismatch found on {0} ({1})'.format(replace_all(name,short_names),host))
    collect_commands=[]
    for row in tbl:
        new_descr= row[4]
        if colorize:
           row[4]= colorize_difs(row[3],row[4])
        print(tabulate([row],['Local Port','Devace Name','Remote Port','Local Description','Expected']))
        print(f'Change this entry to {new_descr} ?')
        if input('(y/n) n ').lower()=='y':
            collect_commands.extend([f'int {row[0]}',f'descr {new_descr}'])
  
    if collect_commands !=[]:
        print('Issue SSH session..')    
        try:
            output=cisco_ssh_command_wr(host,user_name,password,collect_commands)
            if not 'Invalid input' in output:
                print ('successfully done')
            else:
                print('an error has occurred:\n' +output)
        except Exception as e:
            print(e)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check  device via SNMP if  interface descriptions matches  CDP cache.")
    parser.add_argument("-c", dest="community", default='public', help="SNMP community.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-r",metavar='Range', dest="range", help="IP range. E. 192.168.1.1-192.168.2.1 or 192.168.1.1-5")
    group.add_argument("-n",metavar='Network', dest="network", help="IP network. E. 192.168.1.0/24")
    group.add_argument('-a',metavar='Host', dest="hosts",nargs='*', help='Host or hosts lst. E. 192.168.1.0 192.168.1.2')
    group.add_argument('-f',metavar='File', help='Hosts lst  from file.')
    #parser.add_argument('hosts',metavar='Host', nargs='*', help='a host or list of hosts')
    parser.add_argument("-b", action='store_false', help="Do not mark difference")
    parser.add_argument("-i", action='store_true', help="Interactive config mode")
    args = parser.parse_args()
    #args = parser.parse_args('-c [htyfDfv -a 10.142.127.241 -i'.split())

   #print(args)
    if args.b :init(autoreset=True)
    hosts=[]
    if args.hosts!=None:
        hosts=args.hosts
    elif args.range!=None:
        hosts=ip_range(args.range)
    elif args.f!=None:
        hosts=read_file(args.f)
    else:
        net = ipaddress.ip_network(args.network)
        hosts=list(net.hosts())

    for h in hosts:
        main(str(h),args.community,args.b,args.i)
    print ('All done..')