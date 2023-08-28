#from IPython.display import Image, display, display_png
import os, sys, inspect, io, re
from scapy.all import *
import scapy.contrib.mac_control
import numpy
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import logging
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
from scapy.all import *
from ixnetwork_restpy import SessionAssistant
import json
import ssl
import time

import struct
import ipaddress

from datetime import datetime

def aresone_offset(x):
    res = int(float(x) * 0.078125)
    if res >= 20:
        raise Exception(f'odd time offset value: {x} resulted in {res} ns')
    return res

def novus_offset(x):
    res = int(float(x >> 5) * 2.5)
    if res >= 20:
        raise Exception(f'odd time offset value: {x} resulted in {res} ns')
    return res

# aresone - 0.625, novus - 2.5
IXIA_TIME_CONSTANTS = {
    "aresone": aresone_offset,
    "novus": novus_offset
}

def hw_pcap_to_dt(v):
    return pd.to_datetime(int(v * 10**6), unit='ns')

def hw_pcap_to_ns(v):
    return int(v * 10**6)

def decode_hw_ts(p, layer, card):
    if p.haslayer(layer):
        data = bytes(p[layer].payload)[:24]
        s1, s2, s3, s4, s5, s6, offset, p1, p2, p3, seq, ts = struct.unpack("!IIBBBBBBBBII", data)
        if s3 != 0x49 or s4 != 0x78 or s5 != 0x69:
            raise Exception(f'wrong ixia signature in {data}: {s3}, {s4}, {s5}')
        
        #t = ts * 20 + int(float(offset) * 0.078125)
        t = ts * 20 + IXIA_TIME_CONSTANTS[card](offset)
        return t
    raise Exception(f'layer {layer} not present in {p}')
    
def hw_pcap_to_dataframe(filename, card, limit=0):
    res = []
    n = 0
    for p in PcapReader(filename):
        if p.haslayer(IP):
            res.append({
                "sent": decode_hw_ts(p, IP, card),
                "received": hw_pcap_to_ns(p.time),
                "wirelen": p.wirelen,
                "src": p[IP].src,
                "timestamp": hw_pcap_to_dt(p.time),
                "type": "ip",
                "latency": hw_pcap_to_ns(p.time) - decode_hw_ts(p, IP, card)
            })
        if p.haslayer(scapy.contrib.mac_control.MACControlClassBasedFlowControl):
            q = p[scapy.contrib.mac_control.MACControlClassBasedFlowControl]
            res.append({
                "received": hw_pcap_to_ns(p.time),
                "wirelen": p.wirelen,
                "timestamp": hw_pcap_to_dt(p.time),
                "type": "pfc",
                "c0_pause_time": q.c0_pause_time,
                "c0_enabled": q.c0_enabled,
            })
        n = n + 1
        if limit and n >= limit:
            break
    return pd.DataFrame.from_records(res)
    
def get_capture_df(cfiles, pattern, card):
    for cf in [str(x).replace("/tf/mapped/nccl/", "") for x in cfiles]:
        #print(f'looking for {pattern} in {cf}')
        if pattern in cf:
            df = hw_pcap_to_dataframe(cf, card, 0)
            if "sent" in df.columns:
                df["latency"] = df["received"] - df["sent"]            
            return df
    raise Exception(f'{pattern} not found in {cfiles}')

def get_capture_dfs(cfiles, card="novus"):
    m = re.compile(".*(Host-\d-\d)_")
    res = {}
    for cf in [str(x) for x in cfiles]:
        label = m.match(cf).group(1)
        df = get_capture_df(cfiles, label, card)
        res[label] = df
    return res
def get_tail_latency(df, percentile):
    percentile = percentile/100
    latencyList=sorted(df["latency"].tolist())
    ptlat = latencyList[int(percentile*len(latencyList))]
    return ptlat

#session = SessionAssistant(IpAddress='10.36.70.3', RestPort=None, UserName='admin', Password='admin', 
#                              SessionName=None, SessionId=1, ApiKey=None, ClearConfig=False, LogLevel='info')
session = SessionAssistant(IpAddress='10.36.87.216', RestPort=None,  
                               SessionName=None, SessionId=1, ApiKey=None, ClearConfig=False, LogLevel='info')
ixNetwork = session.Ixnetwork
ixNetwork.CloseAllTabs()
#ixNetwork.Traffic.Start()
#time.sleep(10)
ixNetwork.StartCapture()
ixNetwork.Traffic.Start()
time.sleep(10)
ixNetwork.StopCapture()
pathp = ixNetwork.Globals.PersistencePath
res = ixNetwork.SaveCaptureFiles(Arg1=pathp)[0]
cf = "moveFile.cap"
session.Session.DownloadFile(res, cf)
host1_df = hw_pcap_to_dataframe(cf, "novus", 5000)
print(host1_df)
for p in [99, 95, 75, 50]:
    print(p,(get_tail_latency(host1_df, p)))
