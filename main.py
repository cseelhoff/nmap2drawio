import json

diagramName = 'NetworkDiagram'
diagramID = 'NetworkDiagram'
headerOpen = '<mxfile><diagram name="' + diagramName + '" id="' + diagramID + '"><mxGraphModel><root><mxCell id="0" /><mxCell id="1" parent="0" />'
headerClose = '</root></mxGraphModel></diagram></mxfile>'

# a cloud is a switch network of 0.0.0.0/0
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

f = open('data.json')
data = json.load(f)
networksList = data['networksList']
hostsList = data['hostsList']

networkAdapters = {}
connectedNetworks = set()
networks = []
for network in networksList:
    networkName = network['networkName']
    networkID = networkName.replace(".", "_").replace("/","_")
    networkXML = networkTemplate.replace("NetworkID", networkID).replace("NetworkName", networkName)
    outputXML += networkXML
    splitSlash = networkName.split('/')
    octets = splitSlash[0].split('.')
    networkBase10 = int(octets[0]) * 16777216 + int(octets[1]) * 65536 + int(octets[2]) * 256 + int(octets[3])
    allOnes = 2 ** 32
    onesInHostID = 2 ** (32 - int(splitSlash[1]))
    maskBase10 = allOnes - onesInHostID
    networks.append({
        'networkBase10' : networkBase10,
        'maskBase10' : maskBase10,
        'networkID' : networkID
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
        adapterNetworkIndex = -1
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
    for networkServiceIndex in range(len(host['networkServices'])):
        networkService = host['networkServices'][networkServiceIndex]
        serviceID = hostID + '_service_' + str(networkServiceIndex).zfill(3)
        serviceName = networkService['processName'] + '&lt;br&gt;' + networkService['layer7protocol'] + '&lt;br&gt;' + networkService['layer4protocol'] + ' ' + str(networkService['portNumber'])
        serviceXML = networkServiceTemplate.replace('ServiceID', serviceID).replace('ServiceName', serviceName)
        outputXML += serviceXML
        newConnectionXML = connectionTemplate.replace('ConnectionID', serviceID + '_service_connection').replace('ConnectionSource', serviceID).replace('ConnectionTarget', hostID)
        outputXML += newConnectionXML

processedAdapterIDs = set()
processedHostIDs = set()
processedNetworkIDs = set()
lastNetworkCount = -1
while len(processedAdapterIDs) < len(adaptersNetwork): # alternative is < len(adaptersHost)
    #lastNetworkCount = len(networkIDSet)
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

outputXML += headerClose
f = open("network.xml", "w")
f.write(outputXML)
f.close()
