"""
HealthGuard AI: Audit of R1 Logistic Regression (log1p) 0.9999 Test Accuracy
=============================================================================
Investigates the 0.9999 temporal test accuracy of R1 Logistic Regression:
1. Per-class confusion matrix and per-class recall.
2. Single-feature accuracy for each of the 9 R1 features (LR and RF).
3. Drop-one-feature ablation for LR and RF.
4. Feature drift in R1 space (train max exceedance) & nearest-neighbor distance.
5. Unseen traffic classification (normal_iperf, normal_internet1/2/3, scapy).
Outputs saved to results/rate_features/r1_lr_audit.csv.
"""

import os
import time
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import NearestNeighbors
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)

RANDOM_STATE = 42
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
ID_TO_CLASS = {i: n for i, n in enumerate(CLASS_NAMES)}


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


def load_all_r1():
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
    ytr = np.concatenate(y_tr)
    yte = np.concatenate(y_te)

    Xtr_raw = df_tr.values.astype(float)
    Xte_raw = df_te.values.astype(float)

    Xtr_log = apply_log1p(Xtr_raw)
    Xte_log = apply_log1p(Xte_raw)

    return df_tr, df_te, Xtr_raw, Xte_raw, Xtr_log, Xte_log, ytr, yte


def main():
    print("=" * 78)
    print("AUDITING R1 LOGISTIC REGRESSION (LOG1P) — 0.9999 TEST ACCURACY")
    print("=" * 78)
    
    df_tr, df_te, Xtr_raw, Xte_raw, Xtr_log, Xte_log, ytr, yte = load_all_r1()
    print(f"Loaded R1: Train={Xtr_log.shape}, Test={Xte_log.shape}")
    
    # Train the full model
    model = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', LogisticRegression(C=1.0, max_iter=5000, random_state=RANDOM_STATE))
    ])
    model.fit(Xtr_log, ytr)
    y_pred = model.predict(Xte_log)
    acc = accuracy_score(yte, y_pred)
    f1_m = f1_score(yte, y_pred, average='macro', zero_division=0)
    print(f"Full R1 LR log1p Model: Test Accuracy = {acc:.6f} | Macro F1 = {f1_m:.6f}")
    
    audit_sections = []
    
    # -------------------------------------------------------------
    # 1. Per-Class Confusion Matrix & Recall
    # -------------------------------------------------------------
    print("\n" + "=" * 78)
    print("1. PER-CLASS CONFUSION MATRIX AND RECALL")
    print("=" * 78)
    cm = confusion_matrix(yte, y_pred)
    rep = classification_report(yte, y_pred, target_names=CLASS_NAMES, digits=6, output_dict=True)
    
    cm_df = pd.DataFrame(cm, index=CLASS_NAMES, columns=CLASS_NAMES)
    print("\nConfusion Matrix (Rows=True, Cols=Predicted):")
    print(cm_df.to_string())
    
    per_class_rows = []
    for cname in CLASS_NAMES:
        cid = CLASS_TO_ID[cname]
        total = int((yte == cid).sum())
        correct = int(cm[cid, cid])
        errors = total - correct
        rec = rep[cname]['recall']
        prec = rep[cname]['precision']
        f1 = rep[cname]['f1-score']
        per_class_rows.append({
            'Class': cname,
            'Total_Test_Rows': total,
            'Correct': correct,
            'Errors': errors,
            'Recall': round(rec, 6),
            'Precision': round(prec, 6),
            'F1_Score': round(f1, 6)
        })
        print(f"  {cname:<14} total={total:<6} correct={correct:<6} errors={errors:<3} "
              f"recall={rec:.6f} prec={prec:.6f} f1={f1:.6f}")
    per_class_df = pd.DataFrame(per_class_rows)
    
    # Record errors detail
    error_mask = (yte != y_pred)
    n_errors = error_mask.sum()
    print(f"\nTotal Misclassified Rows: {n_errors} out of {len(yte)} ({n_errors/len(yte)*100:.4f}%)")
    if n_errors > 0:
        err_true = [ID_TO_CLASS[y] for y in yte[error_mask]]
        err_pred = [ID_TO_CLASS[y] for y in y_pred[error_mask]]
        err_pairs = pd.Series([f"True: {t} -> Pred: {p}" for t, p in zip(err_true, err_pred)]).value_counts()
        print("Misclassification details:")
        for pair, cnt in err_pairs.items():
            print(f"  {pair}: {cnt} rows")

    # -------------------------------------------------------------
    # 2. Single-Feature Test Accuracy (LR and RF)
    # -------------------------------------------------------------
    print("\n" + "=" * 78)
    print("2. SINGLE-FEATURE ACCURACY (LR AND RF)")
    print("=" * 78)
    single_rows = []
    for i, feat in enumerate(R1_COLS):
        # Feature vector
        Xtr_f = Xtr_log[:, [i]]
        Xte_f = Xte_log[:, [i]]
        
        # LR
        lr_f = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(C=1.0, max_iter=5000, random_state=RANDOM_STATE))
        ])
        lr_f.fit(Xtr_f, ytr)
        pred_lr = lr_f.predict(Xte_f)
        acc_lr = accuracy_score(yte, pred_lr)
        f1_lr = f1_score(yte, pred_lr, average='macro', zero_division=0)
        
        # RF
        rf_f = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)
        rf_f.fit(Xtr_f, ytr)
        pred_rf = rf_f.predict(Xte_f)
        acc_rf = accuracy_score(yte, pred_rf)
        f1_rf = f1_score(yte, pred_rf, average='macro', zero_division=0)
        
        single_rows.append({
            'Feature': feat,
            'LR_Accuracy': round(acc_lr, 4),
            'LR_Macro_F1': round(f1_lr, 4),
            'RF_Accuracy': round(acc_rf, 4),
            'RF_Macro_F1': round(f1_rf, 4),
        })
        print(f"  {feat:<25} | LR Acc = {acc_lr:.4f} (F1 {f1_lr:.4f}) | RF Acc = {acc_rf:.4f} (F1 {f1_rf:.4f})")
    single_df = pd.DataFrame(single_rows)

    # -------------------------------------------------------------
    # 3. Drop-One-Feature Ablation on R1
    # -------------------------------------------------------------
    print("\n" + "=" * 78)
    print("3. DROP-ONE-FEATURE ABLATION (LR AND RF)")
    print("=" * 78)
    ablation_rows = []
    
    # Full RF baseline
    rf_full = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)
    rf_full.fit(Xtr_log, ytr)
    rf_full_acc = accuracy_score(yte, rf_full.predict(Xte_log))
    print(f"Baselines (Full 9): LR = {acc:.6f} | RF = {rf_full_acc:.6f}")
    
    for i, feat in enumerate(R1_COLS):
        keep_idx = [j for j in range(len(R1_COLS)) if j != i]
        Xtr_sub = Xtr_log[:, keep_idx]
        Xte_sub = Xte_log[:, keep_idx]
        
        # LR
        lr_sub = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(C=1.0, max_iter=5000, random_state=RANDOM_STATE))
        ])
        lr_sub.fit(Xtr_sub, ytr)
        acc_lr_sub = accuracy_score(yte, lr_sub.predict(Xte_sub))
        f1_lr_sub = f1_score(yte, lr_sub.predict(Xte_sub), average='macro', zero_division=0)
        
        # RF
        rf_sub = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)
        rf_sub.fit(Xtr_sub, ytr)
        acc_rf_sub = accuracy_score(yte, rf_sub.predict(Xte_sub))
        f1_rf_sub = f1_score(yte, rf_sub.predict(Xte_sub), average='macro', zero_division=0)
        
        diff_lr = acc_lr_sub - acc
        diff_rf = acc_rf_sub - rf_full_acc
        
        ablation_rows.append({
            'Dropped_Feature': feat,
            'LR_Accuracy_Without': round(acc_lr_sub, 6),
            'LR_Macro_F1_Without': round(f1_lr_sub, 6),
            'LR_Delta': round(diff_lr, 6),
            'RF_Accuracy_Without': round(acc_rf_sub, 6),
            'RF_Macro_F1_Without': round(f1_rf_sub, 6),
            'RF_Delta': round(diff_rf, 6),
        })
        print(f"  Drop {feat:<24} | LR Acc={acc_lr_sub:.6f} (Delta {diff_lr:+.6f}) | RF Acc={rf_sub.score(Xte_sub, yte):.4f} (Delta {diff_rf:+.4f})")
    ablation_df = pd.DataFrame(ablation_rows)

    # -------------------------------------------------------------
    # 4. Feature Drift & Nearest-Neighbor Distance in R1 Space
    # -------------------------------------------------------------
    print("\n" + "=" * 78)
    print("4a. FEATURE DRIFT IN R1 SPACE (TRAIN MAX EXCEEDANCE)")
    print("=" * 78)
    drift_detail = []
    class_drift_summary = []
    
    for cname in CLASS_NAMES:
        cid = CLASS_TO_ID[cname]
        tr_c = Xtr_log[ytr == cid]
        te_c = Xte_log[yte == cid]
        n_te = len(te_c)
        
        any_exceed = np.zeros(n_te, dtype=bool)
        
        for j, feat in enumerate(R1_COLS):
            tr_max = float(tr_c[:, j].max())
            feat_exceed = int((te_c[:, j] > tr_max).sum())
            feat_pct = (feat_exceed / n_te) * 100
            any_exceed = any_exceed | (te_c[:, j] > tr_max)
            
            drift_detail.append({
                'Class': cname,
                'Feature': feat,
                'Train_Max': round(tr_max, 4),
                'Test_Max': round(float(te_c[:, j].max()), 4),
                'Test_Rows_Exceeding_Count': feat_exceed,
                'Test_Rows_Exceeding_Pct': round(feat_pct, 2)
            })
            
        any_count = int(any_exceed.sum())
        any_pct = (any_count / n_te) * 100
        class_drift_summary.append({
            'Class': cname,
            'Test_Rows': n_te,
            'Rows_Exceeding_Any_Train_Max': any_count,
            'Percent_Exceeding_Any_Train_Max': round(any_pct, 2)
        })
        print(f"  Class {cname:<14} ({n_te:<5} rows): {any_pct:6.2f}% exceed train max on >=1 R1 feature")
    class_drift_df = pd.DataFrame(class_drift_summary)

    print("\n" + "=" * 78)
    print("4b. NEAREST-NEIGHBOR DISTANCE IN R1 SPACE (20,000 SAMPLE)")
    print("=" * 78)
    # Nearest neighbor in R1 log1p space (same methodology as scripts/_step1_fix.py)
    scaler_r1 = StandardScaler().fit(Xtr_log)
    Xtr_scaled = scaler_r1.transform(Xtr_log)
    
    SAMPLE_N = 20000
    rng = np.random.default_rng(RANDOM_STATE)
    idx_sample = rng.choice(len(Xte_log), size=SAMPLE_N, replace=False)
    Xte_sample_scaled = scaler_r1.transform(Xte_log[idx_sample])
    
    nn = NearestNeighbors(n_neighbors=1, algorithm='auto', n_jobs=-1).fit(Xtr_scaled)
    dist, _ = nn.kneighbors(Xte_sample_scaled)
    d = dist.ravel()
    
    nn_r1_row = {
        'Space': 'R1 (log1p rates)',
        'Train_Rows': int(len(Xtr_log)),
        'Test_Rows_Sampled': int(SAMPLE_N),
        'Median_Distance': round(float(np.median(d)), 6),
        'P90_Distance': round(float(np.percentile(d, 90)), 6),
        'Min_Distance': round(float(d.min()), 6),
        'Max_Distance': round(float(d.max()), 6),
        'Share_Distance_Zero_Pct': round(float((d == 0).mean() * 100), 4),
        'Count_Distance_Zero': int((d == 0).sum()),
        'Share_Distance_Under_0.01_Pct': round(float((d < 0.01).mean() * 100), 4),
        'Share_Distance_Under_0.1_Pct': round(float((d < 0.1).mean() * 100), 4),
    }
    nn_df = pd.DataFrame([nn_r1_row])
    print(nn_df.to_string(index=False))

    # -------------------------------------------------------------
    # 5. Unseen Traffic Generalization
    # -------------------------------------------------------------
    print("\n" + "=" * 78)
    print("5. UNSEEN TRAFFIC EVALUATION WITH R1 LOGISTIC REGRESSION (LOG1P)")
    print("=" * 78)
    unseen_normal_files = [
        ('normal_iperf.csv', 'iPerf throughput generator'),
        ('normal_internet1.csv', 'Internet trace 1'),
        ('normal_internet2.csv', 'Internet trace 2'),
        ('normal_internet3.csv', 'Internet trace 3'),
    ]
    
    unseen_normal_rows = []
    for fname, desc in unseen_normal_files:
        fpath = os.path.join('Archieve', fname)
        df = load_clean(fpath)
        R1_raw = build_r1(df)[R1_COLS].values.astype(float)
        R1_log = apply_log1p(R1_raw)
        preds = model.predict(R1_log)
        pred_labels = [ID_TO_CLASS[p] for p in preds]
        n_tot = len(pred_labels)
        
        counts = pd.Series(pred_labels).value_counts()
        norm_cnt = counts.get('Normal', 0)
        norm_pct = (norm_cnt / n_tot) * 100
        
        non_norm = counts.drop('Normal', errors='ignore')
        top_fps = ", ".join([f"{cls}: {cnt} ({cnt/n_tot*100:.1f}%)" for cls, cnt in non_norm.head(3).items()])
        
        unseen_normal_rows.append({
            'File': fname,
            'Description': desc,
            'Total_Rows': n_tot,
            'Classified_Normal_Count': norm_cnt,
            'Percent_Normal': round(norm_pct, 2),
            'Top_False_Positives': top_fps if len(non_norm) > 0 else 'None'
        })
        print(f"  {fname:<24} ({n_tot:<6} rows) -> Normal: {norm_pct:6.2f}% | False Positives: {top_fps}")
    unseen_norm_df = pd.DataFrame(unseen_normal_rows)

    # Scapy DDoS file
    print("\nUnseen Attack Traffic (ddos_attack_scapy_new.csv):")
    df_scapy = load_clean('Archieve/ddos_attack_scapy_new.csv')
    R1_scapy_raw = build_r1(df_scapy)[R1_COLS].values.astype(float)
    R1_scapy_log = apply_log1p(R1_scapy_raw)
    preds_scapy = model.predict(R1_scapy_log)
    scapy_labels = [ID_TO_CLASS[p] for p in preds_scapy]
    scapy_counts = pd.Series(scapy_labels).value_counts()
    n_scapy = len(scapy_labels)
    
    scapy_rows = []
    for label, count in scapy_counts.items():
        pct = (count / n_scapy) * 100
        scapy_rows.append({
            'File': 'ddos_attack_scapy_new.csv',
            'Predicted_Class': label,
            'Count': count,
            'Percentage': round(pct, 2)
        })
        print(f"  -> {label:<15}: {count:<6} ({pct:6.2f}%)")
    scapy_df = pd.DataFrame(scapy_rows)

    # -------------------------------------------------------------
    # Save Combined Results to results/rate_features/r1_lr_audit.csv
    # -------------------------------------------------------------
    print("\n" + "=" * 78)
    print("SAVING AUDIT CSV TO results/rate_features/r1_lr_audit.csv")
    print("=" * 78)
    
    # We will format r1_lr_audit.csv with a Section column so it can hold all tables cleanly
    audit_master = []
    
    # Section 1: Confusion matrix & recall
    for _, r in per_class_df.iterrows():
        d = dict(r)
        d['Audit_Section'] = '1_Per_Class_Recall'
        audit_master.append(d)
        
    # Section 2: Single feature
    for _, r in single_df.iterrows():
        d = dict(r)
        d['Audit_Section'] = '2_Single_Feature_Accuracy'
        audit_master.append(d)
        
    # Section 3: Ablation
    for _, r in ablation_df.iterrows():
        d = dict(r)
        d['Audit_Section'] = '3_Drop_One_Feature_Ablation'
        audit_master.append(d)
        
    # Section 4a: Drift
    for _, r in class_drift_df.iterrows():
        d = dict(r)
        d['Audit_Section'] = '4a_Class_Drift_Summary'
        audit_master.append(d)
        
    # Section 4b: NN distance
    for _, r in nn_df.iterrows():
        d = dict(r)
        d['Audit_Section'] = '4b_Nearest_Neighbor_Distance'
        audit_master.append(d)
        
    # Section 5: Unseen normal
    for _, r in unseen_norm_df.iterrows():
        d = dict(r)
        d['Audit_Section'] = '5_Unseen_Normal'
        audit_master.append(d)
        
    # Section 5: Scapy
    for _, r in scapy_df.iterrows():
        d = dict(r)
        d['Audit_Section'] = '5_Unseen_Scapy_DDoS'
        audit_master.append(d)
        
    out_master_df = pd.DataFrame(audit_master)
    audit_csv_path = os.path.join(OUT, 'r1_lr_audit.csv')
    out_master_df.to_csv(audit_csv_path, index=False)
    print(f"Saved: {audit_csv_path}")

    # Also save individual clean CSVs for convenience
    per_class_df.to_csv(os.path.join(OUT, 'r1_lr_per_class.csv'), index=False)
    single_df.to_csv(os.path.join(OUT, 'r1_lr_single_feature.csv'), index=False)
    ablation_df.to_csv(os.path.join(OUT, 'r1_lr_ablation.csv'), index=False)
    cm_df.to_csv(os.path.join(OUT, 'r1_lr_confusion_matrix.csv'))
    pd.DataFrame(drift_detail).to_csv(os.path.join(OUT, 'r1_lr_feature_drift_detail.csv'), index=False)
    print(f"Saved supporting CSVs in {OUT}/")


if __name__ == '__main__':
    main()

