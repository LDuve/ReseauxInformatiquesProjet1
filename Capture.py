import pyshark as ps

cap = ps.FileCapture('Capture_Trace_1.pcapng')

print(cap[0][1])