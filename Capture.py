import pyshark as ps
import dns.resolver 
import datetime
import matplotlib.pyplot as plt
import networkx as nx

cap = ps.FileCapture('Capture_Trace_1.pcapng')
DNSResolu = {}
NvResolu = {}
TypeDNS = {}
AddressDst = {}
AddressSrc = {}
AddRecords = []
IPtype = {}


for packet in cap:
    NetworkLayerName = packet.layers[1].layer_name
    
    if NetworkLayerName not in IPtype:
        IPtype[NetworkLayerName] = 1
    else:
        IPtype[NetworkLayerName] +=1

    if 'DNS' in packet:
        
        TransportLayerName = packet.layers[2].layer_name
        domaine = packet.dns.qry_name        

        if hasattr(packet.dns, 'an_count') and int(packet.dns.an_count) > 0:
            additional_records = packet.dns._all_fields[-1].showname.split()[1:]
            AddRecords.append(additional_records)
        
        time = packet.sniff_time.timestamp()
        dt = datetime.datetime.fromtimestamp(time)
        formatted_date = dt.strftime("%d-%m-%Y %H:%M:%S")
        if domaine not in DNSResolu : 
          
            DNSResolu[domaine]= formatted_date
            NvResolu[domaine] = formatted_date
            TypeDNS[domaine] = packet.dns.qry_type
            AddressSrc[domaine] = packet.layers[1].src
            AddressDst[domaine] = packet.layers[1].dst 
        else:
            NvResolu[domaine]= formatted_date

        
        

print(f"{len(NvResolu)} noms de domaine ont ete resolus.")
for domaine, temps_dernier_resolu in NvResolu.items():
    print(f"Le nom de domaine {domaine} a ete resolu pour la derniere fois le {temps_dernier_resolu}.")

for domaine, Typedns in TypeDNS.items():
    print(f"Pour le domaine {domaine}, le type de DNS utilises est {Typedns}.")

print(f"Les types d'adresses IP utlisées sont {IPtype}.")
print(f"Les records additionnels sont {AddRecords}.")

for domaine, destination in AddressDst.items():
    print(f"Les paquets sont envoyes a l'adresse {destination} pour le domaine {domaine}.")

print("\n")

#Partie transport
TransportProtocole = []
domain_ips = {}
Quicversions = []
OtherProto = []
tls_versions = []
timestamps = []
packet_sizes = []
flows = {}

for packet in cap:
    timestamps.append(float(packet.sniff_time.timestamp()))
    packet_sizes.append(int(packet.length))

    if 'QUIC' in packet:
        Quicversions.append(packet.quic.version)

    if 'DNS' in packet:
        if packet.layers[2].layer_name not in TransportProtocole:
            TransportProtocole.append(packet.layers[2].layer_name)  
        
        domaine = packet.dns.qry_name
        srcip = packet.layers[1].src


        if domaine in domain_ips:
            if srcip not in domain_ips[domaine]:
                domain_ips[domaine].append(srcip)
        else:
            domain_ips[domaine] = [srcip]
    if 'UDP' in packet:
        if not 'DNS' in packet and not 'QUIC' in packet: 
            for layer in packet.layers:
                if layer.layer_name not in OtherProto:
                    OtherProto.append(layer.layer_name)
    
    if 'tls' in packet:
        if hasattr(packet.tls, 'record_version'): 
            if packet.tls.record_version not in tls_versions:
                tls_versions.append(packet.tls.record_version)
        v = packet.tls    
        
        




print(f"Le protocole de transport utilise sont {TransportProtocole}.")
for domain, ips in domain_ips.items():
    if len(ips) > 1:
        print(f"Le domaine {domain} a ete contacte par plusieurs adresses IP sources : {ips}")

print(f"Les versions de QUIC utlisee sont : {Quicversions}")
print(f"Lorsque nous observons du trafic UDP, nous identifions aussi {OtherProto}")

print(f"Les differentes versions de TLS utilisees sont : {tls_versions}.")


#Partie graphique
G = nx.Graph()
for packet in cap:
    if 'DNS' in packet:
        src = packet.layers[1].src
        dst = packet.layers[1].dst

        G.add_node(src)
        G.add_node(dst)

        G.add_edge(src, dst)

nx.draw(G, with_labels=True, font_weight='bold')
plt.show()


plt.plot(timestamps, packet_sizes)
plt.xlabel('Temps (secondes)')
plt.ylabel('Taille du paquet (octets)')
plt.title('Graphique temporel de la taille des paquets')
plt.show()

