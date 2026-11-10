"""
Step 1 corrections:
 (a) recompute the LogReg-vs-KNN gaps from results/metrics.csv
 (b) measure nearest-train-row distance for a 20,000-row test sample under
     both the random 80/20 split and the temporal split
 (c) verify the UDPDDOS drift rows in results/feature_drift.csv
Writes results/nearest_neighbor_distance.csv
"""
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import NearestNeighbors
from sklearn.model_selection import train_test_split

RANDOM_STATE = 42
SAMPLE_N = 20000

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


def load_temporal_split(train_ratio=0.70, gap_rows=200):
    tr, te = [], []
    for cname, fp in TC:
        df = pd.read_csv(fp, names=ALL_COLUMNS, low_memory=False)
        for c in F + ['port_duration_sec','ip_duration']:
            df[c] = pd.to_numeric(df[c], errors='coerce')
        df = df.dropna(subset=F).reset_index(drop=True)
        df['type'] = C2I[cname]
        n = len(df); e = int(np.floor(n*train_ratio)); s = e + gap_rows
        a = df.iloc[:e].copy(); a['rel_time'] = np.linspace(0,1,len(a))
        tr.append(a); te.append(df.iloc[s:].copy())
    train_df = pd.concat(tr, ignore_index=True).sort_values('rel_time').reset_index(drop=True)
    test_df = pd.concat(te, ignore_index=True)
    return train_df, test_df


def nn_stats(X_train, X_test_sample, label):
    scaler = StandardScaler().fit(X_train)
    Xtr = scaler.transform(X_train)
    Xte = scaler.transform(X_test_sample)
    nn = NearestNeighbors(n_neighbors=1, algorithm='auto', n_jobs=-1).fit(Xtr)
    dist, _ = nn.kneighbors(Xte)
    d = dist.ravel()
    return {
        'Split': label,
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
    }, d


def main():
    print("=" * 78)
    print("STEP 1a: LogReg vs KNN gaps from results/metrics.csv")
    print("=" * 78)
    m = pd.read_csv('results/metrics.csv')
    lr = m[m['Model'] == 'Logistic Regression'].iloc[0]
    kn = m[m['Model'] == 'KNN'].iloc[0]
    print(f"LogReg Test_Accuracy={lr['Test_Accuracy']}  KNN={kn['Test_Accuracy']}  "
          f"gap={lr['Test_Accuracy']-kn['Test_Accuracy']:.4f}")
    print(f"LogReg Macro_F1     ={lr['Macro_F1']}  KNN={kn['Macro_F1']}  "
          f"gap={lr['Macro_F1']-kn['Macro_F1']:.4f}")
    print(f"LogReg CV_f1_macro  ={lr['CV_f1_macro']}  KNN={kn['CV_f1_macro']}  "
          f"gap={lr['CV_f1_macro']-kn['CV_f1_macro']:.4f}")

    print("\n" + "=" * 78)
    print("STEP 1b: nearest-train-row distance, 20,000-row test sample")
    print("=" * 78)
    train_df, test_df = load_temporal_split()
    full_df = pd.concat([train_df, test_df], ignore_index=True)
    print(f"temporal train={len(train_df)} test={len(test_df)} full={len(full_df)}")

    # --- Random 80/20 split, exactly as evaluate_honest.py builds it ---
    X_all = full_df[F].values
    y_all = full_df['type'].values
    X_tr_rand, X_te_rand, _, _ = train_test_split(
        X_all, y_all, test_size=0.20, random_state=RANDOM_STATE, shuffle=True)
    rng = np.random.default_rng(RANDOM_STATE)
    idx_r = rng.choice(len(X_te_rand), size=SAMPLE_N, replace=False)
    rand_row, d_rand = nn_stats(X_tr_rand, X_te_rand[idx_r], 'Old Random 80/20 Split')
    print(f"random split: train={len(X_tr_rand)} test={len(X_te_rand)}")

    # --- Temporal split ---
    X_tr_temp = train_df[F].values
    X_te_temp = test_df[F].values
    idx_t = rng.choice(len(X_te_temp), size=SAMPLE_N, replace=False)
    temp_row, d_temp = nn_stats(X_tr_temp, X_te_temp[idx_t], 'Temporal 70/30 Split (200-row gap)')

    out = pd.DataFrame([rand_row, temp_row])
    out.to_csv('results/nearest_neighbor_distance.csv', index=False)
    print("\n" + out.to_string(index=False))
    print("\nSaved: results/nearest_neighbor_distance.csv")

    print("\n" + "=" * 78)
    print("STEP 1c: UDPDDOS rows in results/feature_drift.csv")
    print("=" * 78)
    fd = pd.read_csv('results/feature_drift.csv')
    udp = fd[fd['Class'] == 'UDPDDOS'][['Feature','Test_Exceeds_Train_Max_Count',
                                        'Test_Exceeds_Train_Max_Pct']]
    print(udp.to_string(index=False))
    print(f"\nUDPDDOS max drift pct across all features: "
          f"{udp['Test_Exceeds_Train_Max_Pct'].max()}")
    print(f"Any UDPDDOS feature at 100%? "
          f"{bool((udp['Test_Exceeds_Train_Max_Pct'] >= 100.0).any())}")

    print("\nClasses with 100% drift on each counter feature:")
    for feat in ['port_rx_packets','port_rx_bytes','port_tx_bytes']:
        sub = fd[(fd['Feature'] == feat) & (fd['Test_Exceeds_Train_Max_Pct'] >= 100.0)]
        print(f"  {feat:<18} {sorted(sub['Class'].tolist())}")


if __name__ == '__main__':
    main()
