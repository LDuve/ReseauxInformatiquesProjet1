import pyshark as ps

cap = ps.FileCapture('Capture_Trace_1.pcapng')
DNSResolu = {}
NvResolu = {}

for packet in cap:
    if 'DNS' in packet:
        domaine = packet.dns.qry_name

        if domaine not in DNSResolu: 
            DNSResolu[domaine] = packet.sniff_time.timestamp()
            NvResolu[domaine] = packet.sniff_time.timestamp()
        else:
            NvResolu[domaine] = packet.sniff_time.timestamp()

print(f"{len(NvResolu)} noms de domaine ont ete resolus.")
for domaine, temps_dernier_resolu in NvResolu.items():
    print(f"Le nom de domaine '{domaine}' a ete resolu pour la derniere fois a {temps_dernier_resolu}.")