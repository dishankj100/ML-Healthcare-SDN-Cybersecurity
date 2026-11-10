"""
Step 2: Unseen-traffic diagnostics across four model families.

Replicates the temporal split from evaluate_honest.py exactly:
  - 70% train per class, 200-row purge gap, remainder = test
  - FIXED_9_FEATURES only
Hyperparameters are taken from results/metrics.csv Best_Params (tuned on TRAIN ONLY
via TimeSeriesSplit in the original run), so nothing is tuned on test here.

Writes results/unseen_traffic_all_models.csv
"""
import os
import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
import lightgbm as lgb

RANDOM_STATE = 42
RESULTS_DIR = 'results'

ALL_COLUMNS = [
    'src', 'dst', 'table_id', 'ip_bytes', 'ip_packet', 'ip_duration', 'in_port', 'dl_dst', 'port_bytes',
    'port_packet', 'port_flow_count', 'table_active_count', 'table_lookup_count', 'table_matched_count',
    'port_rx_packets', 'port_tx_packets', 'port_rx_bytes', 'port_tx_bytes', 'port_rx_dropped', 'port_tx_dropped',
    'port_rx_errors', 'port_tx_errors', 'port_rx_frame_err', 'port_rx_over_err', 'port_crc_err',
    'port_collisions', 'port_duration_sec'
]

FIXED_9_FEATURES = [
    'ip_bytes', 'ip_packet', 'port_bytes', 'port_packet', 'port_flow_count',
    'table_active_count', 'port_rx_packets', 'port_rx_bytes', 'port_tx_bytes'
]

TRAINING_CLASSES = [
    ('Normal', 'Archieve/normal_ditg.csv'),
    ('BruteForce', 'Archieve/attack_bruteforce.csv'),
    ('CMD', 'Archieve/attack_cmd.csv'),
    ('TCPDDOS', 'Archieve/attack_ddos_tcp.csv'),
    ('UDPDDOS', 'Archieve/attack_ddos_udp.csv'),
    ('Probe', 'Archieve/attack_os_port_scan.csv'),
    ('Smaba', 'Archieve/attack_samba.csv'),
    ('SQLInjection', 'Archieve/attack_sql_injection.csv'),
    ('VNC', 'Archieve/attack_vnc.csv'),
]
CLASS_NAMES = sorted([c[0] for c in TRAINING_CLASSES])
CLASS_TO_ID = {name: idx for idx, name in enumerate(CLASS_NAMES)}
ID_TO_CLASS = {idx: name for idx, name in enumerate(CLASS_NAMES)}


def load_temporal_split(train_ratio=0.70, gap_rows=200):
    train_chunks, test_chunks, summary = [], [], []
    for cname, fpath in TRAINING_CLASSES:
        df = pd.read_csv(fpath, names=ALL_COLUMNS, low_memory=False)
        for col in FIXED_9_FEATURES + ['port_duration_sec', 'ip_duration']:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        df = df.dropna(subset=FIXED_9_FEATURES).reset_index(drop=True)
        df['type'] = CLASS_TO_ID[cname]
        n = len(df)
        train_end = int(np.floor(n * train_ratio))
        test_start = train_end + gap_rows
        tr = df.iloc[:train_end].copy()
        tr['rel_time'] = np.linspace(0, 1, len(tr))
        train_chunks.append(tr)
        test_chunks.append(df.iloc[test_start:].copy())
        summary.append({'class': cname, 'total_rows': n,
                        'train_rows': train_end, 'test_rows': n - test_start})
    train_df = pd.concat(train_chunks, ignore_index=True)
    # Match evaluate_honest.py: sort train by intra-class relative time progress
    train_df = train_df.sort_values('rel_time').reset_index(drop=True)
    test_df = pd.concat(test_chunks, ignore_index=True)
    return train_df, test_df, pd.DataFrame(summary)


def load_unseen(fpath):
    df = pd.read_csv(fpath, names=ALL_COLUMNS, low_memory=False)
    for col in FIXED_9_FEATURES:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    return df.dropna(subset=FIXED_9_FEATURES)


def build_models():
    # Hyperparameters copied from results/metrics.csv Best_Params (train-only tuning)
    return {
        'Logistic Regression (scaled)': Pipeline([
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(C=0.1, max_iter=500, random_state=RANDOM_STATE))
        ]),
        'KNN (scaled)': Pipeline([
            ('scaler', StandardScaler()),
            ('knn', KNeighborsClassifier(n_neighbors=7, n_jobs=-1))
        ]),
        'LightGBM': lgb.LGBMClassifier(
            n_estimators=100, num_leaves=31, learning_rate=0.2,
            random_state=RANDOM_STATE, n_jobs=-1, verbose=-1
        ),
        'Random Forest': RandomForestClassifier(
            n_estimators=100, max_depth=None, min_samples_split=2,
            random_state=RANDOM_STATE, n_jobs=-1
        ),
    }


def main():
    print("=" * 78)
    print("STEP 2: Unseen-traffic diagnostics across four model families")
    print("=" * 78)

    train_df, test_df, summary = load_temporal_split()
    print("\nTemporal split summary:")
    print(summary.to_string(index=False))
    print(f"\nTrain rows: {len(train_df)}  Test rows: {len(test_df)}")

    X_train = train_df[FIXED_9_FEATURES].values
    y_train = train_df['type'].values
    X_test = test_df[FIXED_9_FEATURES].values
    y_test = test_df['type'].values

    unseen_normal = [
        ('normal_iperf.csv', 'Normal (iPerf load generator)'),
        ('normal_internet1.csv', 'Normal (Internet trace 1)'),
        ('normal_internet2.csv', 'Normal (Internet trace 2)'),
        ('normal_internet3.csv', 'Normal (Internet trace 3)'),
    ]
    attack_file = ('ddos_attack_scapy_new.csv', 'Unseen Attack (Scapy DDoS)')

    unseen_cache = {}
    for fname, _ in unseen_normal + [attack_file]:
        unseen_cache[fname] = load_unseen(os.path.join('Archieve', fname))
        print(f"  loaded {fname:<28} rows={len(unseen_cache[fname])}")

    models = build_models()
    rows = []

    for name, model in models.items():
        print(f"\n[fit] {name} ...", flush=True)
        model.fit(X_train, y_train)

        test_acc = float((model.predict(X_test) == y_test).mean())
        print(f"       temporal test accuracy = {test_acc*100:.2f}%")

        for fname, desc in unseen_normal:
            df = unseen_cache[fname]
            preds = model.predict(df[FIXED_9_FEATURES].values)
            labels = pd.Series([ID_TO_CLASS[p] for p in preds])
            n = len(labels)
            counts = labels.value_counts()
            normal_n = int(counts.get('Normal', 0))
            normal_pct = normal_n / n * 100.0
            non_normal = counts.drop('Normal', errors='ignore')
            fp_str = ", ".join(f"{c}: {int(v)} ({v/n*100:.2f}%)"
                               for c, v in non_normal.head(4).items()) or 'None'
            rows.append({
                'Model': name,
                'File': fname,
                'Traffic_Type': 'Unseen Normal',
                'Total_Rows': n,
                'Classified_As_Normal_Count': normal_n,
                'Percent_Normal': round(normal_pct, 2),
                'Label_Distribution': ", ".join(f"{c}: {int(v)} ({v/n*100:.2f}%)"
                                                for c, v in counts.items()),
                'Top_Non_Normal_Labels': fp_str,
                'Temporal_Test_Accuracy': round(test_acc, 4),
            })
            print(f"       {fname:<24} Normal={normal_pct:6.2f}%  ({normal_n}/{n})")

        fname, desc = attack_file
        df = unseen_cache[fname]
        preds = model.predict(df[FIXED_9_FEATURES].values)
        labels = pd.Series([ID_TO_CLASS[p] for p in preds])
        n = len(labels)
        counts = labels.value_counts()
        rows.append({
            'Model': name,
            'File': fname,
            'Traffic_Type': 'Unseen Attack (Scapy DDoS)',
            'Total_Rows': n,
            'Classified_As_Normal_Count': int(counts.get('Normal', 0)),
            'Percent_Normal': round(int(counts.get('Normal', 0)) / n * 100.0, 2),
            'Label_Distribution': ", ".join(f"{c}: {int(v)} ({v/n*100:.2f}%)"
                                            for c, v in counts.items()),
            'Top_Non_Normal_Labels': ", ".join(f"{c}: {int(v)} ({v/n*100:.2f}%)"
                                               for c, v in counts.drop('Normal', errors='ignore').items()) or 'None',
            'Temporal_Test_Accuracy': round(test_acc, 4),
        })
        print(f"       {fname:<24} distribution: " +
              ", ".join(f"{c}={v/n*100:.2f}%" for c, v in counts.items()))

    out = pd.DataFrame(rows)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    outpath = os.path.join(RESULTS_DIR, 'unseen_traffic_all_models.csv')
    out.to_csv(outpath, index=False)
    print(f"\nSaved: {outpath}  ({len(out)} rows)")

    print("\n" + "=" * 78)
    print("PERCENT NORMAL BY MODEL AND FILE")
    print("=" * 78)
    piv = out.pivot_table(index='File', columns='Model', values='Percent_Normal', sort=False)
    print(piv.to_string())


if __name__ == '__main__':
    main()
