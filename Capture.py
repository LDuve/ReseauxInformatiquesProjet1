import pyshark as ps
import dns.resolver 
import datetime

cap = ps.FileCapture('Capture_Trace_1.pcapng')
DNSResolu = {}
NvResolu = {}
TypeDNS = {}
AddressDst = {}
AddressSrc = {}
AddRecords = []

for packet in cap:
    if 'DNS' in packet:
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
            if 'ipv6' in packet:
                AddressSrc[domaine] = packet.ipv6.src
                AddressDst[domaine] = packet.ipv6.dst
            elif 'ipv4' in packet:
                NvResolu[domaine] = packet.ipv4.src
                AddressDst[domaine] = packet.ipv4.dst
            elif 'ip' in packet:
                NvResolu[domaine] = packet.ip.src
                AddressDst[domaine] = packet.ip.dst
       
        else:
            NvResolu[domaine]= formatted_date

        
        

print(f"{len(NvResolu)} noms de domaine ont ete resolus.")
for domaine, temps_dernier_resolu in NvResolu.items():
    print(f"Le nom de domaine '{domaine}' a ete resolu pour la derniere fois le {temps_dernier_resolu}.")

print(f"Les differents type DNS utilises sont {TypeDNS}.")
print(f"Les records additionnels sont {AddRecords}.")

for domaine, destination in AddressDst.items():
    print(f"Les paquets sont envoyes a l'adresse {destination} pour le domaine {domaine}.")


