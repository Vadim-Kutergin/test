#!/usr/bin/env python

import sys
import ipaddress
import argparse
from pysnmp import hlapi
from tabulate import tabulate
from colorama import init, Fore, Back, Style
import difflib

import paramiko
import time
import socket

def replace_all(text, dic):
    for i, j in dic.items():
        text = text.replace(i, j)
    return text

def colorize_difs(s1,s2,color=Fore.BLUE, skip_threshold=30):
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
    ip1=int(ipaddress.IPv4Address(ips[0]))
    ip2=int(ipaddress.IPv4Address(ips[1]))
    if ip1>ip2:
        ip1,ip2=ip2,ip1
    return [str(ipaddress.IPv4Address(i)) for i in range(ip1,ip2+1)]




def snmp_get(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    handler = hlapi.getCmd(
        engine,
        credentials,
        hlapi.UdpTransportTarget((target, port),timeout=.5, retries=0),
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
             engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    handler = hlapi.bulkCmd(
        engine,
        credentials,
        hlapi.UdpTransportTarget((target, port)),
        context,
        start_from, count,
        *construct_object_types(oids)
    )
    return fetch(handler, count)

def snmp_get_bulk_auto(target, oids, credentials, count_oid, start_from=0, port=161,
                  engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    count = snmp_get(target, [count_oid], credentials, port, engine, context)[count_oid]
    return snmp_get_bulk(target, oids, credentials, count, start_from, port, engine, context)




def snmp_walk(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    handler= hlapi.nextCmd(engine, credentials, hlapi.UdpTransportTarget((target, port)), context,
        *construct_object_types(oids),lexicographicMode=False)
    return fetch_auto(handler)


#https://pyneng.readthedocs.io/ru/latest/book/18_ssh_telnet/paramiko.html
def send_show_command(ip,username,password,enable,commands,max_bytes=60000,short_pause=0.5,long_pause=5):
    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cl.connect(hostname=ip,username=username,password=password,look_for_keys=False,allow_agent=False)
    with cl.invoke_shell() as ssh:
        ssh.send("enable\n")
        ssh.send(f"{enable}\n")
        time.sleep(short_pause)
        ssh.send("terminal length 0\n")
        time.sleep(short_pause)
        ssh.recv(max_bytes)

        result = {}
        for command in commands:
            ssh.send(f"{command}\n")
            ssh.settimeout(long_pause)

            output = ""
            while True:
                try:
                    part = ssh.recv(max_bytes).decode("utf-8")
                    output += part
                    time.sleep(short_pause)
                except socket.timeout:
                    break
            result[command] = output

        return result




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

def main(host,comm,colorize):
    try:
        name = get_name(host, comm)
        tbl= get_table(host,comm)
    except RuntimeError as err:
        print (f'{host}',err)
        return

    if tbl==[]:
        return
    if colorize:
        for i in range(len(tbl)):
            tbl[i][4]= colorize_difs(tbl[i][3],tbl[i][4])

    print('\nDescripton mismatch found on {0} ({1})'.format(replace_all(name,short_names),host))
    print(tabulate(tbl,['Local Port','Devace Name','Remote Port','Local Description','Expected']))
    print ('\n')




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check  device via SNMP if  interface descriptions matches  CDP cache.")
    parser.add_argument("-c", dest="community", default='public', help="SNMP community.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-r",metavar='Range', dest="range", help="IP range.  192.168.1.1-192.168.2.1")
    group.add_argument("-n",metavar='Network', dest="network", help="IP network.  192.168.1.0/24")
    group.add_argument('-a',metavar='Host', dest="hosts",nargs='*', help='Host or hosts lst. 192.168.1.0 192.168.1.2')
    #parser.add_argument('hosts',metavar='Host', nargs='*', help='a host or list of hosts')
    parser.add_argument("-b", action='store_false', help="Do not mark difference")
    parser.add_argument("-i", action='store_true', help="Interactive config mode")
    args = parser.parse_args()

    #print(args)
    if args.b :init(autoreset=True)
    hosts=[]
    if args.hosts!=None:
        hosts=args.hosts
    elif args.range!=None:
        hosts=ip_range(args.range)
    else:
        net = ipaddress.ip_network(args.network)
        hosts=list(net.hosts())

    for h in hosts:
        main(str(h),args.community,args.b)

