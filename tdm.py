from scapy.all import *
from pprint import pprint
from scapy.layers.l2 import Ether, ARP
import sys


def arp_scan(ip):

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    ans, unans = srp(request, timeout=2, retry=1, verbose=0)
    result = []

    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return result


if __name__ == "__main__":
    mac = sys.argv[1].lower() if len(sys.argv) > 1 else 'a6:2f:23:fb:89:00'
    d = arp_scan('192.168.1.1/24')
    for i in d:
        if i['MAC'] == mac:
            print(i['IP'])
            exit(0)
    print('Not found', file=sys.stderr)
    exit(1)
