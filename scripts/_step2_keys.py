"""Can deltas be keyed on (cycle, in_port, src, dst)? Check uniqueness and monotonicity."""
import numpy as np, pandas as pd

ALL_COLUMNS = ['src','dst','table_id','ip_bytes','ip_packet','ip_duration','in_port','dl_dst','port_bytes',
 'port_packet','port_flow_count','table_active_count','table_lookup_count','table_matched_count',
 'port_rx_packets','port_tx_packets','port_rx_bytes','port_tx_bytes','port_rx_dropped','port_tx_dropped',
 'port_rx_errors','port_tx_errors','port_rx_frame_err','port_rx_over_err','port_crc_err',
 'port_collisions','port_duration_sec']
F = ['ip_bytes','ip_packet','port_bytes','port_packet','port_flow_count',
     'table_active_count','port_rx_packets','port_rx_bytes','port_tx_bytes']
TC = [('Normal','Archieve/normal_ditg.csv'),('BruteForce','Archieve/attack_bruteforce.csv'),
 ('CMD','Archieve/attack_cmd.csv'),('TCPDDOS','Archieve/attack_ddos_tcp.csv'),
 ('UDPDDOS','Archieve/attack_ddos_udp.csv'),('Probe','Archieve/attack_os_port_scan.csv'),
 ('Smaba','Archieve/attack_samba.csv'),('SQLInjection','Archieve/attack_sql_injection.csv'),
 ('VNC','Archieve/attack_vnc.csv')]

print(f"{'Class':<14}{'rows':<8}{'dup(cyc,in_port)':<19}{'dup(cyc,in_port,src,dst)':<26}{'keys':<8}{'rx_bytes monotonic':<20}")
for cname, fp in TC:
    df = pd.read_csv(fp, names=ALL_COLUMNS, low_memory=False)
    for c in F + ['port_duration_sec','ip_duration']:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    df = df.dropna(subset=F).reset_index(drop=True)
    pdur = df['port_duration_sec'].values
    ch = np.flatnonzero(np.diff(pdur) != 0) + 1
    starts = np.concatenate(([0], ch)); ends = np.concatenate((ch, [len(df)]))
    rl = ends - starts
    df['cyc'] = np.repeat(np.arange(len(rl)), rl)

    d1 = int(df.duplicated(subset=['cyc','in_port']).sum())
    d2 = int(df.duplicated(subset=['cyc','in_port','src','dst']).sum())
    nkeys = df.groupby(['cyc','in_port','src','dst']).ngroups

    # monotonicity of port_rx_bytes per full flow key across cycles
    piv = df.pivot_table(index='cyc', columns=['in_port','src','dst'],
                         values='port_rx_bytes', aggfunc='first')
    diffs = piv.diff().iloc[1:]
    neg = int((diffs < 0).sum().sum()); tot = int(diffs.notna().sum().sum())
    mono = f"{neg} neg / {tot} ({neg/tot*100:.2f}%)" if tot else "n/a"
    print(f"{cname:<14}{len(df):<8}{d1:<19}{d2:<26}{nkeys:<8}{mono:<20}")
