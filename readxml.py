import xml.etree.ElementTree as ET
tree = ET.parse('nmap.xml')
root = tree.getroot()

ipToHosts = {}
routerIPs = set()
ipToPorts = {}
networks = set()
hostsToIPs = {}

for child1 in root:
    if child1.tag == 'host':
        for child2 in child1:
            if child2.tag == 'trace':
                for child2index in range(len(child2)):
                    child3 = child2[child2index]
                    if child3.tag == 'hop':
                        ipaddr = child3.attrib['ipaddr']
                        octets = ipaddr.split('.')
                        network = octets[0] + '.' + octets[1] + '.' + octets[2] + '.0/24'
                        networks.add(network)
                        if ipaddr not in ipToHosts:
                            ipToHosts[ipaddr] = set()
                        if ipaddr not in ipToPorts:
                            ipToPorts[ipaddr] = set()
                        if 'host' in child3.attrib:
                            host = child3.attrib['host']
                            ipToHosts[ipaddr].add(host)                            
                            if host not in hostsToIPs:
                                hostsToIPs[host] = set()
                            hostsToIPs[host].add(ipaddr)
                        if child2index < len(child2) - 1:
                            routerIPs.add(ipaddr)
for child1 in root:
    if child1.tag == 'host':
        print("HOST:")
        for child2 in child1:
            if child2.tag == 'address' and child2.attrib['addrtype'] == 'ipv4':
                print("  ADDRESS: ", child2.attrib['addr'])
                ipaddr = child2.attrib['addr']
                octets = ipaddr.split('.')
                network = octets[0] + '.' + octets[1] + '.' + octets[2] + '.0/24'
                networks.add(network)
                if ipaddr not in ipToHosts:
                    ipToHosts[ipaddr] = set()
                if ipaddr not in ipToPorts:
                    ipToPorts[ipaddr] = set()
                for child2 in child1:
                    if child2.tag == 'hostnames':
                        for hostname in child2.attrib:
                            ipToHosts[ipaddr].add(hostname)
                            if hostname not in hostsToIPs:
                                hostsToIPs[hostname] = set()
                            hostsToIPs[hostname].add(ipaddr)
                    if child2.tag == 'ports':
                        for child3 in child2:
                            if child3.tag == 'port':
                                ipToPorts[ipaddr].add(child3.attrib['protocol'] + ":" + child3.attrib['portid'])
for ip in ipToHosts:
    if len(ipToHosts[ip]) == 0:
        ipToHosts[ip].add(ip)
        hostsToIPs[ip] = set()
        hostsToIPs[ip].add(ip)

jsondata = {}
jsondata['networksList'] = []

print('Networks:')
for network in networks:
    print(network)
    jsondata['networksList'].append({
        "networkName": network,
        "isRootNetwork": False
    })

jsondata['networksList'].append({
    "networkName": "0.0.0.0/0",
    "isRootNetwork": True
})
print('---')

hostsCompleted = set()
jsondata['hostsList'] = []
for host in hostsToIPs:
    if host in hostsCompleted:
        continue
    allHostnames = set()
    for ip in hostsToIPs[host]:
        for host in ipToHosts[ip]:
            allHostnames.add(host)
            hostsCompleted.add(host)
    print('hostName: ' + host)
    print('hostNames: ' + str(allHostnames))
    networkAdapters = []
    networkServices = []
    for ip in hostsToIPs[host]:
        print('  IP: ' + ip)
        networkAdapters.append({
            "adapterName": ip,
            "adapterIP": ip
        })
        for port in ipToPorts[ip]:
            print('    Port: ' + port)
            splitPort = port.split(':')
            networkServices.append({
                "layer4protocol": splitPort[0],
                "portNumber": splitPort[1],
                "layer7protocol": "",
                "processName": ""
            })
    print('Is Router: ' + str(ip in routerIPs))
    print('---')
    jsondata['hostsList'].append({
        "hostName": host,
        "routesTraffic": (ip in routerIPs),
        "networkAdapters": networkAdapters,
        "networkServices": networkServices
    })

import json
with open('data2.json', 'w', encoding='utf-8') as f:
    json.dump(jsondata, f, ensure_ascii=False, indent=4)
