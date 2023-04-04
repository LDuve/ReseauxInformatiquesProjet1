import pyshark as ps
import dns.resolver 
import datetime

cap = ps.FileCapture('Capture_Trace_1.pcapng')
DNSResolu = {}
NvResolu = {}
TypeDNS = []
AddRecords = []

for packet in cap:
    if 'DNS' in packet:
        domaine = packet.dns.qry_name

        if hasattr(packet.dns, 'an_count') and int(packet.dns.an_count) > 0:
            # Extraire les enregistrements additionnels
            additional_records = packet.dns._all_fields[-1].showname.split()[1:]
            AddRecords.append(additional_records)

        if domaine not in DNSResolu : 
            time = packet.sniff_time.timestamp()
            dt = datetime.datetime.fromtimestamp(time)
            formatted_date = dt.strftime("%d-%m-%Y %H:%M:%S")

            DNSResolu[domaine] = formatted_date
            NvResolu[domaine] = formatted_date
            query_type = packet.dns.qry_type
            TypeDNS.append(query_type)
        else:
            NvResolu[domaine] = formatted_date

print(f"{len(NvResolu)} noms de domaine ont ete resolus.")
for domaine, temps_dernier_resolu in NvResolu.items():
    print(f"Le nom de domaine '{domaine}' a ete resolu pour la derniere fois le {temps_dernier_resolu}.")
print(f"les differents type DNS utilises sont {TypeDNS}.")
print(f"Les records additionnels sont {AddRecords}.")
