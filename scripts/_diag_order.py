"""Diagnose why my RF/LGBM temporal accuracy differs from results/metrics.csv."""
import numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
import lightgbm as lgb

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
CN = sorted([c[0] for c in TC]); C2I = {n:i for i,n in enumerate(CN)}

tr, te = [], []
for cname, fp in TC:
    df = pd.read_csv(fp, names=ALL_COLUMNS, low_memory=False)
    for c in F + ['port_duration_sec','ip_duration']:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    df = df.dropna(subset=F).reset_index(drop=True)
    df['type'] = C2I[cname]
    n = len(df); e = int(np.floor(n*0.70)); s = e+200
    a = df.iloc[:e].copy(); a['rel_time'] = np.linspace(0,1,len(a))
    tr.append(a); te.append(df.iloc[s:].copy())

train_concat = pd.concat(tr, ignore_index=True)
test_df = pd.concat(te, ignore_index=True)
train_sorted = train_concat.sort_values('rel_time').reset_index(drop=True)

print(f"train rows: concat={len(train_concat)} sorted={len(train_sorted)}  test={len(test_df)}")
print(f"same set: {set(map(tuple, train_concat[F].values)) == set(map(tuple, train_sorted[F].values))}")

y_test = test_df['type'].values
X_test = test_df[F].values

for tag, trn in [('CONCAT order (unsorted)', train_concat), ('SORTED by rel_time', train_sorted)]:
    X_tr = trn[F].values; y_tr = trn['type'].values
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_tr, y_tr)
    acc = (rf.predict(X_test) == y_test).mean()
    lg = lgb.LGBMClassifier(random_state=42, n_jobs=-1, verbose=-1)
    lg.fit(X_tr, y_tr)
    lacc = (lg.predict(X_test) == y_test).mean()
    print(f"{tag:<26} RF acc={acc:.4f}   LGBM(default) acc={lacc:.4f}")
