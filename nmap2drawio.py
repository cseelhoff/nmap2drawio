#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import json
import argparse
import sys


def parse_nmap_xml(input_file):
    tree = ET.parse(input_file)
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
            for child2 in child1:
                if child2.tag == 'address' and child2.attrib['addrtype'] == 'ipv4':
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

    for network in networks:
        jsondata['networksList'].append({
            "networkName": network,
            "isRootNetwork": False
        })

    jsondata['networksList'].append({
        "networkName": "0.0.0.0/0",
        "isRootNetwork": True
    })

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
        networkAdapters = []
        networkServices = []
        for ip in hostsToIPs[host]:
            networkAdapters.append({
                "adapterName": ip,
                "adapterIP": ip
            })
            for port in ipToPorts[ip]:
                splitPort = port.split(':')
                networkServices.append({
                    "layer4protocol": splitPort[0],
                    "portNumber": splitPort[1],
                    "layer7protocol": "",
                    "processName": ""
                })
        jsondata['hostsList'].append({
            "hostName": host,
            "routesTraffic": (ip in routerIPs),
            "networkAdapters": networkAdapters,
            "networkServices": networkServices
        })

    return jsondata


def generate_drawio(data, output_file, include_processes=True):
    diagramName = 'NetworkDiagram'
    diagramID = 'NetworkDiagram'
    headerOpen = '<mxfile><diagram name="' + diagramName + '" id="' + diagramID + '"><mxGraphModel><root><mxCell id="0" /><mxCell id="1" parent="0" />'
    headerClose = '</root></mxGraphModel></diagram></mxfile>'

    cloudWidth = 120
    cloudHeight = 80
    cloudTemplate = '<mxCell id="CloudID" value="CloudName" style="shape=cloud;" vertex="1" parent="1"><mxGeometry width="' + str(cloudWidth) + '" height="' + str(cloudHeight) + '" as="geometry" /></mxCell>'

    networkWidth = 50
    networkHeight = 50
    networkTemplate = '<mxCell id="NetworkID" value="NetworkName" style="verticalLabelPosition=bottom;html=1;shape=mxgraph.cisco19.rect;prIcon=l2_switch;" vertex="1" parent="1"><mxGeometry width="' + str(networkWidth) + '" height="' + str(networkHeight) + '" as="geometry" /></mxCell>'

    routerWidth = 60
    routerHeight = 60
    routerTemplate = '<mxCell id="RouterID" value="RouterName" style="verticalLabelPosition=bottom;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.router;" vertex="1" parent="1"><mxGeometry width="' + str(routerWidth) + '" height="' + str(routerHeight) + '" as="geometry" /></mxCell>'

    adapterWidth = 50
    adapterHeight = 50
    networkAdapterTemplate = '<mxCell id="AdapterID" value="AdapterName&lt;br&gt;AdapterIP" style="html=1;strokeColor=none;fillColor=#000000;verticalLabelPosition=bottom;verticalAlign=top;shape=mxgraph.vvd.ethernet_port;" vertex="1" parent="1"><mxGeometry width="' + str(adapterWidth) + '" height="' + str(adapterHeight) + '" as="geometry" /></mxCell>'

    workstationWidth = 53
    workstationHeight = 56
    workstationTemplate = '<mxCell id="WorkstationID" value="WorkstationName" style="html=1;fillColor=#0079D6;verticalLabelPosition=bottom;shape=mxgraph.office.devices.workstation;" vertex="1" parent="1"><mxGeometry width="' + str(workstationWidth) + '" height="' + str(workstationHeight) + '" as="geometry" /></mxCell>'

    serviceWidth = 120
    serviceHeight = 70
    networkServiceTemplate = '<mxCell id="ServiceID" value="ServiceName" style="html=1;fillColor=#0079D6;verticalAlign=bottom;spacingTop=-6;fontColor=#FFFFFF;shape=mxgraph.sitemap.services;direction=west;" vertex="1" parent="1"><mxGeometry width="' + str(serviceWidth) + '" height="' + str(serviceHeight) + '" as="geometry" /></mxCell>'

    connectionTemplate = '<mxCell id="ConnectionID" edge="1" parent="1" source="ConnectionSource" target="ConnectionTarget"><mxGeometry as="geometry" /></mxCell>'

    outputXML = headerOpen

    networksList = data['networksList']
    hostsList = data['hostsList']

    networkAdapters = {}
    connectedNetworks = set()
    networks = []
    for network in networksList:
        networkName = network['networkName']
        networkID = networkName.replace(".", "_").replace("/", "_")
        networkXML = networkTemplate.replace("NetworkID", networkID).replace("NetworkName", networkName)
        outputXML += networkXML
        splitSlash = networkName.split('/')
        octets = splitSlash[0].split('.')
        networkBase10 = int(octets[0]) * 16777216 + int(octets[1]) * 65536 + int(octets[2]) * 256 + int(octets[3])
        allOnes = 2 ** 32
        onesInHostID = 2 ** (32 - int(splitSlash[1]))
        maskBase10 = allOnes - onesInHostID
        networks.append({
            'networkBase10': networkBase10,
            'maskBase10': maskBase10,
            'networkID': networkID
        })
        networkAdapters[networkID] = []
        if network['isRootNetwork']:
            connectedNetworks.add(networkID)

    hostAdapters = {}
    adaptersHost = {}
    adaptersNetwork = {}
    for hostIndex in range(len(hostsList)):
        hostID = 'host_' + str(hostIndex).zfill(4)
        hostAdapters[hostID] = []
        host = hostsList[hostIndex]
        hostXML = ''
        if host['routesTraffic'] == True:
            hostXML = routerTemplate.replace('RouterID', hostID).replace('RouterName', host['hostName'])
        else:
            hostXML = workstationTemplate.replace('WorkstationID', hostID).replace('WorkstationName', host['hostName'])
        outputXML += hostXML
        for networkAdapter in host['networkAdapters']:
            adapterIP = networkAdapter['adapterIP']
            octets = adapterIP.split('.')
            addressBase10 = int(octets[0]) * 16777216 + int(octets[1]) * 65536 + int(octets[2]) * 256 + int(octets[3])
            adapterName = networkAdapter['adapterName']
            adapterID = hostID + '_' + adapterName
            hostAdapters[hostID].append(adapterID)
            adaptersHost[adapterID] = hostID
            adapterXML = networkAdapterTemplate.replace('AdapterID', adapterID).replace('AdapterName', adapterName).replace('AdapterIP', adapterIP)
            outputXML += adapterXML
            for networkIndex in range(len(networks)):
                network = networks[networkIndex]
                maskedNetworkBase10 = addressBase10 & network['maskBase10']
                if maskedNetworkBase10 == network['networkBase10']:
                    networkID = network['networkID']
                    networkAdapters[networkID].append(adapterID)
                    adaptersNetwork[adapterID] = networkID
                    break
        if include_processes:
            for networkServiceIndex in range(len(host['networkServices'])):
                networkService = host['networkServices'][networkServiceIndex]
                serviceID = hostID + '_service_' + str(networkServiceIndex).zfill(3)
                serviceName = networkService['processName'] + '&lt;br&gt;' + networkService['layer7protocol'] + '&lt;br&gt;' + networkService['layer4protocol'] + ' ' + str(networkService['portNumber'])
                serviceXML = networkServiceTemplate.replace('ServiceID', serviceID).replace('ServiceName', serviceName)
                outputXML += serviceXML

    processedAdapterIDs = set()
    processedHostIDs = set()
    processedNetworkIDs = set()
    while len(processedAdapterIDs) < len(adaptersNetwork):
        lastConnectedNetworksCount = len(connectedNetworks)
        lastHostCount = len(processedHostIDs)
        lastProcessedNetworkIDCount = len(processedNetworkIDs)
        lastAdapterCount = len(processedAdapterIDs)

        for networkID in connectedNetworks:
            if networkID in processedNetworkIDs:
                continue
            for adapterID in networkAdapters[networkID]:
                if adapterID in processedAdapterIDs:
                    continue
                newConnectionXML = connectionTemplate.replace('ConnectionID', adapterID + '_switch_connection').replace('ConnectionSource', adapterID).replace('ConnectionTarget', networkID)
                outputXML += newConnectionXML
                processedAdapterIDs.add(adapterID)
                hostID = adaptersHost[adapterID]
                if hostID in processedHostIDs:
                    continue
                newConnectionXML = connectionTemplate.replace('ConnectionID', adapterID + '_host_connection').replace('ConnectionSource', hostID).replace('ConnectionTarget', adapterID)
                outputXML += newConnectionXML
                processedHostIDs.add(hostID)
            processedNetworkIDs.add(networkID)

        for hostID in processedHostIDs:
            adapterIDs = hostAdapters[hostID]
            for adapterID in adapterIDs:
                if adapterID in processedAdapterIDs:
                    continue
                newConnectionXML = connectionTemplate.replace('ConnectionID', adapterID + '_host_connection').replace('ConnectionSource', adapterID).replace('ConnectionTarget', hostID)
                outputXML += newConnectionXML
                processedAdapterIDs.add(adapterID)
                networkID = adaptersNetwork[adapterID]
                if networkID in processedNetworkIDs:
                    continue
                connectedNetworks.add(networkID)
                newConnectionXML = connectionTemplate.replace('ConnectionID', adapterID + '_switch_connection').replace('ConnectionSource', networkID).replace('ConnectionTarget', adapterID)
                outputXML += newConnectionXML

        if lastConnectedNetworksCount != len(connectedNetworks):
            continue
        if lastHostCount != len(processedHostIDs):
            continue
        if lastProcessedNetworkIDCount != len(processedNetworkIDs):
            continue
        if lastAdapterCount != len(processedAdapterIDs):
            continue

        for network in networks:
            if network['networkID'] not in connectedNetworks:
                connectedNetworks.add(network['networkID'])
                break

    outputXML += headerClose
    with open(output_file, 'w') as f:
        f.write(outputXML)


def main():
    parser = argparse.ArgumentParser(description='Convert nmap XML scan to draw.io network diagram')
    parser.add_argument('-i', '--input', required=True, help='Input nmap XML scan file')
    parser.add_argument('-o', '--output', required=True, help='Output draw.io XML file')
    parser.add_argument('--includeProcesses', default='y', choices=['y', 'n'], help='Include processes in the diagram (default: y)')
    args = parser.parse_args()

    data = parse_nmap_xml(args.input)
    generate_drawio(data, args.output, include_processes=(args.includeProcesses == 'y'))
    print(f'Diagram written to {args.output}')


if __name__ == '__main__':
    main()
