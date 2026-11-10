"""
HealthGuard AI: Live Replay Model Training Script
=================================================
Trains a Random Forest (100 trees, random_state=42) on R1 single-row rate features
using the temporal TRAIN set only.

Outputs:
- live_model.joblib (model, scaler, feature metadata)
- results/live_replay/model_metrics.csv (honest test accuracy, macro F1, weighted F1)
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

RANDOM_STATE = 42
OUT_DIR = 'results/live_replay'
os.makedirs(OUT_DIR, exist_ok=True)

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
ID_TO_CLASS = {i: n for i, n in enumerate(CLASS_NAMES)}


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
    print("=" * 78)
    print("TRAINING LIVE REPLAY MODEL (RANDOM FOREST ON R1 TEMPORAL TRAIN SET)")
    print("=" * 78)

    r1_tr, r1_te = [], []
    y_tr, y_te = [], []

    for cname, fp in TC:
        df = load_clean(fp)
        n = len(df)
        train_end = int(np.floor(n * 0.70))
        test_start = train_end + 200
        lab = CLASS_TO_ID[cname]

        R1 = build_r1(df)
        tr_idx = np.arange(0, train_end)
        te_idx = np.arange(test_start, n)

        r1_tr.append(R1.iloc[tr_idx])
        y_tr.append(np.full(len(tr_idx), lab))
        r1_te.append(R1.iloc[te_idx])
        y_te.append(np.full(len(te_idx), lab))

    df_tr = pd.concat(r1_tr, ignore_index=True)[R1_COLS]
    df_te = pd.concat(r1_te, ignore_index=True)[R1_COLS]
    y_train = np.concatenate(y_tr)
    y_test = np.concatenate(y_te)

    X_train_raw = df_tr.values.astype(float)
    X_test_raw = df_te.values.astype(float)

    print(f"Dataset loaded: Train={X_train_raw.shape}, Test={X_test_raw.shape}")

    # 1. Apply log1p to rate features
    X_train_log = apply_log1p(X_train_raw)
    X_test_log = apply_log1p(X_test_raw)

    # 2. Fit StandardScaler strictly on the train partition
    scaler = StandardScaler().fit(X_train_log)
    X_train_scaled = scaler.transform(X_train_log)
    X_test_scaled = scaler.transform(X_test_log)

    # 3. Train Random Forest (100 trees, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)
    print("Random Forest fit complete.")

    # 4. Evaluate on the temporal test set
    y_pred = rf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    prec_macro = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec_macro = recall_score(y_test, y_pred, average='macro', zero_division=0)
    f1_mac = f1_score(y_test, y_pred, average='macro', zero_division=0)
    f1_weight = f1_score(y_test, y_pred, average='weighted', zero_division=0)

    print(f"\nHonest Evaluation on Held-Out Temporal Test Set:")
    print(f"  Test Accuracy:     {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Macro Precision:   {prec_macro:.4f}")
    print(f"  Macro Recall:      {rec_macro:.4f}")
    print(f"  Macro F1:          {f1_mac:.4f}")
    print(f"  Weighted F1:       {f1_weight:.4f}")

    # 5. Save model bundle
    bundle = {
        'model': rf,
        'scaler': scaler,
        'feature_names': R1_COLS,
        'log_features': R1_LOG,
        'class_names': CLASS_NAMES,
        'class_to_id': CLASS_TO_ID,
        'id_to_class': ID_TO_CLASS,
        'metrics': {
            'test_accuracy': round(float(acc), 4),
            'macro_f1': round(float(f1_mac), 4),
            'weighted_f1': round(float(f1_weight), 4)
        }
    }
    model_path = 'live_model.joblib'
    joblib.dump(bundle, model_path)
    print(f"\nSaved live model bundle to: {model_path} (model.sav was NOT modified)")

    # 6. Save metrics CSV
    metrics_df = pd.DataFrame([{
        'Model': 'Random Forest (100 trees, R1, log1p rates)',
        'Train_Rows': int(len(X_train_raw)),
        'Test_Rows': int(len(X_test_raw)),
        'Test_Accuracy': round(float(acc), 4),
        'Macro_Precision': round(float(prec_macro), 4),
        'Macro_Recall': round(float(rec_macro), 4),
        'Macro_F1': round(float(f1_mac), 4),
        'Weighted_F1': round(float(f1_weight), 4),
        'Random_State': RANDOM_STATE,
        'Scaling': 'StandardScaler (fit on train only)',
        'Log_Transformed_Features': ", ".join(R1_LOG)
    }])
    metrics_csv = os.path.join(OUT_DIR, 'model_metrics.csv')
    metrics_df.to_csv(metrics_csv, index=False)
    print(f"Saved honest metrics to: {metrics_csv}")

    # Per-class classification report
    rep = classification_report(y_test, y_pred, target_names=CLASS_NAMES, output_dict=True, zero_division=0)
    per_class_rows = []
    for cname in CLASS_NAMES:
        per_class_rows.append({
            'Class': cname,
            'Precision': round(rep[cname]['precision'], 4),
            'Recall': round(rep[cname]['recall'], 4),
            'F1_Score': round(rep[cname]['f1-score'], 4),
            'Support': int(rep[cname]['support'])
        })
    pd.DataFrame(per_class_rows).to_csv(os.path.join(OUT_DIR, 'per_class_metrics.csv'), index=False)
    print(f"Saved per-class report to: {OUT_DIR}/per_class_metrics.csv")


if __name__ == '__main__':
    main()
