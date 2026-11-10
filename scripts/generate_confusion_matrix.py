import os
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

ALL_COLUMNS = [
    'src','dst','table_id','ip_bytes','ip_packet','ip_duration','in_port','dl_dst','port_bytes',
    'port_packet','port_flow_count','table_active_count','table_lookup_count','table_matched_count',
    'port_rx_packets','port_tx_packets','port_rx_bytes','port_tx_bytes','port_rx_dropped','port_tx_dropped',
    'port_rx_errors','port_tx_errors','port_rx_frame_err','port_rx_over_err','port_crc_err',
    'port_collisions','port_duration_sec'
]

F9 = ['ip_bytes','ip_packet','port_bytes','port_packet','port_flow_count',
      'table_active_count','port_rx_packets','port_rx_bytes','port_tx_bytes']

R1_COLS = [
    'ip_bytes', 'ip_packet', 'ip_bytes_per_packet',
    'port_rx_bytes_rate', 'port_tx_bytes_rate', 'port_rx_packets_rate',
    'port_rx_bytes_per_packet', 'port_flow_count', 'table_active_count'
]

R1_LOG = [
    'ip_bytes_per_packet', 'port_rx_bytes_rate', 'port_tx_bytes_rate',
    'port_rx_packets_rate', 'port_rx_bytes_per_packet'
]

TC = [
    ('Normal','Archieve/normal_ditg.csv'),
    ('BruteForce','Archieve/attack_bruteforce.csv'),
    ('CMD','Archieve/attack_cmd.csv'),
    ('TCPDDOS','Archieve/attack_ddos_tcp.csv'),
    ('UDPDDOS','Archieve/attack_ddos_udp.csv'),
    ('Probe','Archieve/attack_os_port_scan.csv'),
    ('Smaba','Archieve/attack_samba.csv'),
    ('SQLInjection','Archieve/attack_sql_injection.csv'),
    ('VNC','Archieve/attack_vnc.csv')
]

CLASS_NAMES = sorted([c[0] for c in TC])
CLASS_TO_ID = {n: i for i, n in enumerate(CLASS_NAMES)}

def load_clean(fp):
    df = pd.read_csv(fp, names=ALL_COLUMNS, low_memory=False)
    for c in F9 + ['port_duration_sec', 'ip_duration']:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    return df.dropna(subset=F9).reset_index(drop=True)

def build_r1(df):
    out = pd.DataFrame(index=df.index)
    out['ip_bytes'] = df['ip_bytes'].astype(float)
    out['ip_packet'] = df['ip_packet'].astype(float)
    out['ip_bytes_per_packet'] = np.where(
        df['ip_packet'] > 0,
        df['ip_bytes'] / df['ip_packet'].replace(0, np.nan), 0.0
    )
    pds = df['port_duration_sec'].astype(float)
    out['port_rx_bytes_rate'] = df['port_rx_bytes'] / pds
    out['port_tx_bytes_rate'] = df['port_tx_bytes'] / pds
    out['port_rx_packets_rate'] = df['port_rx_packets'] / pds
    out['port_rx_bytes_per_packet'] = np.where(
        df['port_rx_packets'] > 0,
        df['port_rx_bytes'] / df['port_rx_packets'].replace(0, np.nan), 0.0
    )
    out['port_flow_count'] = df['port_flow_count'].astype(float)
    out['table_active_count'] = df['table_active_count'].astype(float)
    return out

def apply_log1p(X, cols=R1_COLS, log_cols=R1_LOG):
    X = X.copy()
    idx = [cols.index(c) for c in log_cols]
    X[:, idx] = np.log1p(np.clip(X[:, idx], 0, None))
    return X

def main():
    bundle = joblib.load('live_model.joblib')
    model = bundle['model']
    scaler = bundle['scaler']

    r1_te, y_te = [], []
    for cname, fp in TC:
        df = load_clean(fp)
        n = len(df)
        train_end = int(np.floor(n * 0.70))
        test_start = train_end + 200
        lab = CLASS_TO_ID[cname]

        R1 = build_r1(df)
        te_idx = np.arange(test_start, n)
        r1_te.append(R1.iloc[te_idx])
        y_te.append(np.full(len(te_idx), lab))

    df_te = pd.concat(r1_te, ignore_index=True)[R1_COLS]
    y_test = np.concatenate(y_te)
    X_test_raw = df_te.values.astype(float)
    X_test_log = apply_log1p(X_test_raw)
    X_test_scaled = scaler.transform(X_test_log)

    y_pred = model.predict(X_test_scaled)
    cm = confusion_matrix(y_test, y_pred, labels=range(len(CLASS_NAMES)))

    cm_df = pd.DataFrame(cm, index=[f"True_{c}" for c in CLASS_NAMES], columns=[f"Pred_{c}" for c in CLASS_NAMES])
    os.makedirs('results/live_replay', exist_ok=True)
    out_csv = 'results/live_replay/confusion_matrix.csv'
    cm_df.to_csv(out_csv)
    print(f"Confusion Matrix saved to {out_csv}:")
    print(cm_df)

    # Check SQLInjection specifically
    sqli_idx = CLASS_TO_ID['SQLInjection']
    print(f"\nBreakdown for SQLInjection (True label index {sqli_idx}, total {cm[sqli_idx].sum()}):")
    for j, cname in enumerate(CLASS_NAMES):
        cnt = cm[sqli_idx, j]
        if cnt > 0:
            print(f"  Predicted as {cname}: {cnt} ({cnt / cm[sqli_idx].sum() * 100:.2f}%)")

    # Check CMD precision / predictions
    cmd_idx = CLASS_TO_ID['CMD']
    print(f"\nBreakdown for predictions as CMD (Pred label index {cmd_idx}, total {cm[:, cmd_idx].sum()}):")
    for i, cname in enumerate(CLASS_NAMES):
        cnt = cm[i, cmd_idx]
        if cnt > 0:
            print(f"  True {cname}: {cnt} ({cnt / cm[:, cmd_idx].sum() * 100:.2f}%)")

if __name__ == '__main__':
    main()

