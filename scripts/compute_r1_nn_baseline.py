import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import NearestNeighbors

RANDOM_STATE = 42
SAMPLE_N = 20000
OUT = 'results/rate_features'
os.makedirs(OUT, exist_ok=True)

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
    for c in F9 + ['port_duration_sec','ip_duration']:
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


def nn_stats(X_train, X_test_sample, label, space='R1 (log1p rates)'):
    scaler = StandardScaler().fit(X_train)
    Xtr = scaler.transform(X_train)
    Xte = scaler.transform(X_test_sample)
    nn = NearestNeighbors(n_neighbors=1, algorithm='auto', n_jobs=-1).fit(Xtr)
    dist, _ = nn.kneighbors(Xte)
    d = dist.ravel()
    return {
        'Split': label,
        'Feature_Space': space,
        'Train_Rows': int(len(X_train)),
        'Test_Rows_Sampled': int(len(X_test_sample)),
        'Median_Distance': round(float(np.median(d)), 6),
        'P90_Distance': round(float(np.percentile(d, 90)), 6),
        'Min_Distance': round(float(d.min()), 6),
        'Max_Distance': round(float(d.max()), 6),
        'Share_Distance_Zero_Pct': round(float((d == 0).mean() * 100), 4),
        'Count_Distance_Zero': int((d == 0).sum()),
        'Share_Distance_Under_0.01_Pct': round(float((d < 0.01).mean() * 100), 4),
        'Share_Distance_Under_0.1_Pct': round(float((d < 0.1).mean() * 100), 4),
    }


def main():
    print("Computing nearest-neighbour baseline in R1 log1p space...")
    
    # Load all files
    r1_all = []
    y_all = []
    r1_tr_temp = []
    r1_te_temp = []
    y_tr_temp = []
    y_te_temp = []
    
    for cname, fp in TC:
        df = load_clean(fp)
        n = len(df)
        train_end = int(np.floor(n * 0.70))
        test_start = train_end + 200
        lab = CLASS_TO_ID[cname]

        R1 = build_r1(df)[R1_COLS]
        
        # Whole file
        r1_all.append(R1)
        y_all.append(np.full(n, lab))
        
        # Temporal split parts
        r1_tr_temp.append(R1.iloc[:train_end])
        y_tr_temp.append(np.full(train_end, lab))
        r1_te_temp.append(R1.iloc[test_start:])
        y_te_temp.append(np.full(n - test_start, lab))
        
    df_all = pd.concat(r1_all, ignore_index=True)
    y_all = np.concatenate(y_all)
    X_all_log = apply_log1p(df_all.values.astype(float))
    
    # 1. Random 80/20 split in R1 space
    X_tr_rand, X_te_rand, y_tr_rand, y_te_rand = train_test_split(
        X_all_log, y_all, test_size=0.20, random_state=RANDOM_STATE, shuffle=True
    )
    rng = np.random.default_rng(RANDOM_STATE)
    idx_r = rng.choice(len(X_te_rand), size=SAMPLE_N, replace=False)
    rand_row = nn_stats(X_tr_rand, X_te_rand[idx_r], 'Random 80/20 Split (R1 space)')
    
    # 2. Temporal 70/30 split in R1 space
    df_tr_t = pd.concat(r1_tr_temp, ignore_index=True)
    df_te_t = pd.concat(r1_te_temp, ignore_index=True)
    X_tr_temp = apply_log1p(df_tr_t.values.astype(float))
    X_te_temp = apply_log1p(df_te_t.values.astype(float))
    idx_t = rng.choice(len(X_te_temp), size=SAMPLE_N, replace=False)
    temp_row = nn_stats(X_tr_temp, X_te_temp[idx_t], 'Temporal 70/30 Split with 200-row gap (R1 space)')
    
    out_df = pd.DataFrame([rand_row, temp_row])
    out_path = os.path.join(OUT, 'r1_nn_baseline.csv')
    out_df.to_csv(out_path, index=False)
    
    print("\n" + "=" * 80)
    print("NEAREST-NEIGHBOR DISTANCES IN R1 SPACE (SAME-SPACE COMPARISON)")
    print("=" * 80)
    print(out_df.to_string(index=False))
    print(f"\nSaved to: {out_path}")


if __name__ == '__main__':
    main()
