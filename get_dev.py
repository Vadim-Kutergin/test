from msilib.schema import Error
from  check_descriptions import get_name,ip_range,replace_all
import ipaddress
import argparse
import paramiko


short_names ={'.si.rt.ru':''}
def main(host,comm,skip_empty,timeout):
    try:
        cl = paramiko.SSHClient()
        cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cl.connect(hostname=host,username='',password='',look_for_keys=False,allow_agent=False,timeout=timeout)
    except TimeoutError as e:
       return
    except paramiko.SSHException:
        pass

    name=''
    if comm!='':
        try:
            name= get_name(host,comm)
        except RuntimeError:
            pass
    if name=='' and  skip_empty:
        return
    print (f'{host};{replace_all(name,short_names)}')



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for devices with an open SSh port.")
    parser.add_argument("-c", dest="community", help="Optional SNMP community to get device name.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-r",metavar='Range', dest="range", nargs='*',help="IP range. E. 192.168.1.1-192.168.2.1 or 192.168.1.1-5")
    group.add_argument("-n",metavar='Network', dest="network",nargs='*' ,help="IP network. E. 192.168.1.0/24")
    parser.add_argument("-s", action='store_true', help="Skip device if name is empty or not received.")
    parser.add_argument("-t", type=float,default=.4, help="Open socket timeout")

    args = parser.parse_args()
    #args = parser.parse_args('-c [htyfDfv -r 10.142.127.0-4'.split())

    #print(args)
    hosts=[]

    if args.range!=None:
        for r in args.range:
            hosts.append(ip_range(r))
    else:
        for n in args.network:
            net = ipaddress.ip_network(n)
            hosts.append(list(net.hosts()))
    for i in hosts:
        for h in i:
            main(str(h),args.community,args.s,args.t)
    print ('All done..')