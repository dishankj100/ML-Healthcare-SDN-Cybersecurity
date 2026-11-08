"""
HealthGuard AI: Honest & Reproducible Machine Learning Evaluation
==================================================================
This script replaces the leaky 100%-accuracy evaluation with a strictly honest,
temporal, reproducible evaluation methodology.

Sections:
- STEP 1: Chronological Row Order Verification (Addition 1)
- STEP 2: Temporal Partitioning (70% train, 200-row purge gap, ~30% test)
- STEP 3: Multi-Model TimeSeriesSplit CV Tuning & Test Evaluation (8 Models)
- STEP 4: Diagnostic 1 - Old-Style Random Split vs Temporal Split
- STEP 5: Diagnostic 2 - Feature Ablation (Drop table_active_count & port_tx_bytes)
- STEP 6: Diagnostic 3 - Exact Duplicate Feature Rows Analysis
- STEP 7: Diagnostic 4 - Unseen Normal Traffic Generalization
- STEP 8: Diagnostic 5 - Unseen Attack Traffic Evaluation (Scapy)
- STEP 9: Diagnostic 6 - Feature Drift & Range Invariant Analysis (Addition 2)
- STEP 10: Export Structured CSVs and Confusion Matrix Plot to results/
"""

import os
import sys
import time
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import TimeSeriesSplit, GridSearchCV, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression

import xgboost as xgb
import lightgbm as lgb

# ---------------------------------------------------------
# Global Schema & Constants
# ---------------------------------------------------------
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

# Alphabetical class label mapping (matches label_encoder.fit_transform)
CLASS_NAMES = sorted([c[0] for c in TRAINING_CLASSES])
CLASS_TO_ID = {name: idx for idx, name in enumerate(CLASS_NAMES)}
ID_TO_CLASS = {idx: name for idx, name in enumerate(CLASS_NAMES)}

RANDOM_STATE = 42
RESULTS_DIR = 'results'


def verify_chronological_ordering(data_folder='Archieve'):
    """
    Checks whether port_duration_sec (and ip_duration) is non-decreasing along row order.
    Returns a dataframe of findings. Raises RuntimeError if any file is not time-ordered.
    """
    print("\n" + "=" * 80, flush=True)
    print("STEP 1: Chronological Row Order Verification (Addition 1)", flush=True)
    print("=" * 80, flush=True)
    
    files_to_check = [fpath for _, fpath in TRAINING_CLASSES] + [
        f'{data_folder}/normal_iperf.csv',
        f'{data_folder}/normal_internet1.csv',
        f'{data_folder}/normal_internet2.csv',
        f'{data_folder}/normal_internet3.csv',
        f'{data_folder}/ddos_attack_scapy_new.csv',
    ]
    
    results = []
    for fpath in files_to_check:
        if not os.path.exists(fpath):
            continue
        fname = os.path.basename(fpath)
        df = pd.read_csv(fpath, names=ALL_COLUMNS, usecols=['ip_duration', 'port_duration_sec'], low_memory=False)
        df['port_duration_sec'] = pd.to_numeric(df['port_duration_sec'], errors='coerce')
        df['ip_duration'] = pd.to_numeric(df['ip_duration'], errors='coerce')
        df = df.dropna(subset=['port_duration_sec', 'ip_duration'])
        n = len(df)
        
        port_diff = df['port_duration_sec'].diff().dropna()
        port_decr = (port_diff < 0).sum()
        port_decr_pct = (port_decr / (n - 1)) * 100 if n > 1 else 0.0
        
        ip_diff = df['ip_duration'].diff().dropna()
        ip_decr = (ip_diff < 0).sum()
        ip_decr_pct = (ip_decr / (n - 1)) * 100 if n > 1 else 0.0
        
        p_start = df['port_duration_sec'].iloc[0]
        p_end = df['port_duration_sec'].iloc[-1]
        
        is_ordered = port_decr_pct <= 0.05  # threshold: allow <= 0.05% jitter/rollover
        results.append({
            'file': fname,
            'clean_rows': n,
            'port_dur_decr_pct': round(port_decr_pct, 4),
            'ip_dur_decr_pct': round(ip_decr_pct, 2),
            'port_start_sec': p_start,
            'port_end_sec': p_end,
            'chronological_status': 'PASS' if is_ordered else 'FAIL'
        })
        
        print(f"[{'PASS' if is_ordered else 'FAIL'}] {fname:<28} rows: {n:<7} "
              f"port_dur decr: {port_decr_pct:6.4f}% | ip_dur decr: {ip_decr_pct:6.2f}% | "
              f"uptime: {p_start:.0f}s -> {p_end:.0f}s", flush=True)
        
        if not is_ordered:
            raise RuntimeError(f"CRITICAL: {fname} is clearly not time-ordered (port_duration_sec decr: {port_decr_pct}%). Execution halted.")
            
    print("-> All files confirmed strictly chronological. OpenFlow switch uptime (port_duration_sec) monotonically advances.", flush=True)
    return pd.DataFrame(results)


def load_temporal_split(train_ratio=0.70, gap_rows=200):
    """
    Loads raw CSVs, enforces temporal splitting within each file:
    first 70% = train, 200-row purge gap, remaining ~30% = test.
    Preserves exact row order without pre-shuffling.
    """
    print("\n" + "=" * 80, flush=True)
    print(f"STEP 2: Loading Data with Temporal Split ({int(train_ratio*100)}% train, {gap_rows}-row gap)", flush=True)
    print("=" * 80, flush=True)
    
    train_chunks = []
    test_chunks = []
    summary = []
    
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
        # Add intra-class relative time progress in [0, 1]
        tr['rel_time'] = np.linspace(0, 1, len(tr))
        train_chunks.append(tr)
        
        te = df.iloc[test_start:].copy()
        test_chunks.append(te)
        
        summary.append({
            'class': cname,
            'class_id': CLASS_TO_ID[cname],
            'total_rows': n,
            'train_rows': len(tr),
            'gap_purged': test_start - train_end,
            'test_rows': len(te)
        })
        print(f"  Class {CLASS_TO_ID[cname]} ({cname:<13}): Total={n:<6} | Train={len(tr):<6} | Gap={gap_rows:<3} | Test={len(te):<6}", flush=True)
        
    train_df = pd.concat(train_chunks, ignore_index=True)
    # Sort train by relative time progress so TimeSeriesSplit folds contain all 9 classes chronologically
    train_df = train_df.sort_values('rel_time').reset_index(drop=True)
    test_df = pd.concat(test_chunks, ignore_index=True)
    
    print(f"\nCombined Train Set: {train_df.shape[0]} rows across 9 classes", flush=True)
    print(f"Combined Test Set:  {test_df.shape[0]} rows across 9 classes", flush=True)
    
    return train_df, test_df, pd.DataFrame(summary)


def get_model_specs():
    """
    Returns the dictionary of 8 models and their hyperparameter tuning grids.
    Tuned strictly on train using TimeSeriesSplit (3 splits) scoring f1_macro.
    """
    models = {
        'Decision Tree': {
            'estimator': DecisionTreeClassifier(random_state=RANDOM_STATE),
            'param_grid': {
                'max_depth': [5, 10, 15, None],
                'min_samples_split': [2, 10]
            }
        },
        'Random Forest': {
            'estimator': RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1),
            'param_grid': {
                'max_depth': [10, 15, None],
                'min_samples_split': [2, 5]
            }
        },
        'KNN': {
            'estimator': Pipeline([
                ('scaler', StandardScaler()),
                ('knn', KNeighborsClassifier(n_jobs=-1))
            ]),
            'param_grid': {
                'knn__n_neighbors': [3, 5, 7]
            }
        },
        'Naive Bayes': {
            'estimator': GaussianNB(),
            'param_grid': {
                'var_smoothing': [1e-9, 1e-8, 1e-7]
            }
        },
        'Logistic Regression': {
            'estimator': Pipeline([
                ('scaler', StandardScaler()),
                ('clf', LogisticRegression(max_iter=500, random_state=RANDOM_STATE))
            ]),
            'param_grid': {
                'clf__C': [0.1, 1.0, 10.0]
            }
        },
        'AdaBoost': {
            'estimator': AdaBoostClassifier(random_state=RANDOM_STATE),
            'param_grid': {
                'n_estimators': [50, 100],
                'learning_rate': [0.1, 1.0]
            }
        },
        'XGBoost': {
            'estimator': xgb.XGBClassifier(
                random_state=RANDOM_STATE, n_jobs=-1, eval_metric='mlogloss'
            ),
            'param_grid': {
                'n_estimators': [50, 100],
                'max_depth': [4, 6],
                'learning_rate': [0.1, 0.2]
            }
        },
        'LightGBM': {
            'estimator': lgb.LGBMClassifier(
                random_state=RANDOM_STATE, n_jobs=-1, verbose=-1
            ),
            'param_grid': {
                'n_estimators': [50, 100],
                'num_leaves': [31, 63],
                'learning_rate': [0.1, 0.2]
            }
        }
    }
    return models


def evaluate_models_temporal(train_df, test_df, features=FIXED_9_FEATURES, cv_splits=3):
    """
    Tunes all 8 models on train_df using TimeSeriesSplit scoring f1_macro.
    Fits best estimator on full train_df, evaluates on test_df.
    Computes all metrics with (y_true, y_pred) call order.
    """
    print("\n" + "=" * 80, flush=True)
    print("STEP 3: Multi-Model TimeSeriesSplit Cross-Validation Tuning & Evaluation", flush=True)
    print("=" * 80, flush=True)
    
    X_train = train_df[features].values
    y_train = train_df['type'].values
    X_test = test_df[features].values
    y_test = test_df['type'].values
    
    tscv = TimeSeriesSplit(n_splits=cv_splits)
    specs = get_model_specs()
    
    metrics_list = []
    per_class_rows = []
    confusion_matrices = {}
    best_models = {}
    
    for name, spec in specs.items():
        print(f"\n[Training & Tuning] {name}...", flush=True)
        t0 = time.time()
        
        # Grid search over train only using TimeSeriesSplit
        grid = GridSearchCV(
            estimator=spec['estimator'],
            param_grid=spec['param_grid'],
            cv=tscv,
            scoring='f1_macro',
            n_jobs=-1 if name not in ['Random Forest', 'KNN', 'XGBoost', 'LightGBM'] else 1
        )
        grid.fit(X_train, y_train)
        tune_time = time.time() - t0
        best_estimator = grid.best_estimator_
        best_models[name] = best_estimator
        
        print(f"  Best params: {grid.best_params_} (CV f1_macro: {grid.best_score_:.4f}) in {tune_time:.1f}s", flush=True)
        
        # Final prediction on held-out temporal test set
        t_eval = time.time()
        y_pred = best_estimator.predict(X_test)
        eval_time = time.time() - t_eval
        
        # Compute metrics strictly with (y_true, y_pred)
        acc = accuracy_score(y_test, y_pred)
        prec_macro = precision_score(y_test, y_pred, average='macro', zero_division=0)
        rec_macro = recall_score(y_test, y_pred, average='macro', zero_division=0)
        f1_mac = f1_score(y_test, y_pred, average='macro', zero_division=0)
        
        prec_weight = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        rec_weight = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1_weight = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        metrics_list.append({
            'Model': name,
            'CV_f1_macro': round(grid.best_score_, 4),
            'Test_Accuracy': round(acc, 4),
            'Macro_Precision': round(prec_macro, 4),
            'Macro_Recall': round(rec_macro, 4),
            'Macro_F1': round(f1_mac, 4),
            'Weighted_Precision': round(prec_weight, 4),
            'Weighted_Recall': round(rec_weight, 4),
            'Weighted_F1': round(f1_weight, 4),
            'Best_Params': str(grid.best_params_),
            'Tune_Time_Sec': round(tune_time, 2),
            'Eval_Time_Sec': round(eval_time, 2)
        })
        
        # Per class classification report
        rep = classification_report(y_test, y_pred, target_names=CLASS_NAMES, output_dict=True, zero_division=0)
        for cname in CLASS_NAMES:
            per_class_rows.append({
                'Model': name,
                'Class': cname,
                'Precision': round(rep[cname]['precision'], 4),
                'Recall': round(rep[cname]['recall'], 4),
                'F1_Score': round(rep[cname]['f1-score'], 4),
                'Support': int(rep[cname]['support'])
            })
            
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        confusion_matrices[name] = cm
        
        print(f"  -> Honest Test Acc: {acc*100:6.2f}% | Macro F1: {f1_mac:6.4f} | Weighted F1: {f1_weight:6.4f}", flush=True)
        
    metrics_df = pd.DataFrame(metrics_list)
    per_class_df = pd.DataFrame(per_class_rows)
    return metrics_df, per_class_df, confusion_matrices, best_models


# ---------------------------------------------------------
# TASK B: Leakage & Generalization Diagnostics
# ---------------------------------------------------------

def run_diagnostic_random_vs_temporal(train_df, test_df):
    """
    Diagnostic 1 & 3: Old-style random 80/20 split vs the new temporal split.
    Counts exact duplicate feature rows for both split types.
    """
    print("\n" + "=" * 80, flush=True)
    print("STEP 4: Diagnostic 1 & 3 - Random Split vs Temporal Split & Duplicates", flush=True)
    print("=" * 80, flush=True)
    
    # Recreate the complete dataset across all 9 classes (unsplit)
    full_df = pd.concat([train_df, test_df], ignore_index=True)
    
    # 1. Random 80/20 split (seeded 42)
    X_all = full_df[FIXED_9_FEATURES].values
    y_all = full_df['type'].values
    X_tr_rand, X_te_rand, y_tr_rand, y_te_rand = train_test_split(
        X_all, y_all, test_size=0.20, random_state=RANDOM_STATE, shuffle=True
    )
    
    rf_rand = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)
    rf_rand.fit(X_tr_rand, y_tr_rand)
    y_pred_rand = rf_rand.predict(X_te_rand)
    
    acc_rand = accuracy_score(y_te_rand, y_pred_rand)
    f1_rand = f1_score(y_te_rand, y_pred_rand, average='macro', zero_division=0)
    
    # 2. Duplicate counting for Random Split
    df_tr_rand = pd.DataFrame(X_tr_rand, columns=FIXED_9_FEATURES)
    df_te_rand = pd.DataFrame(X_te_rand, columns=FIXED_9_FEATURES)
    set_tr_rand = set(map(tuple, df_tr_rand.values))
    dups_in_test_rand = sum(tuple(row) in set_tr_rand for row in df_te_rand.values)
    dups_pct_rand = (dups_in_test_rand / len(df_te_rand)) * 100
    
    # 3. Duplicate counting for Temporal Split
    df_tr_temp = train_df[FIXED_9_FEATURES]
    df_te_temp = test_df[FIXED_9_FEATURES]
    set_tr_temp = set(map(tuple, df_tr_temp.values))
    dups_in_test_temp = sum(tuple(row) in set_tr_temp for row in df_te_temp.values)
    dups_pct_temp = (dups_in_test_temp / len(df_te_temp)) * 100
    
    # 4. Temporal RF performance
    rf_temp = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)
    rf_temp.fit(train_df[FIXED_9_FEATURES].values, train_df['type'].values)
    y_pred_temp = rf_temp.predict(test_df[FIXED_9_FEATURES].values)
    acc_temp = accuracy_score(test_df['type'].values, y_pred_temp)
    f1_temp = f1_score(test_df['type'].values, y_pred_temp, average='macro', zero_division=0)
    
    comp_df = pd.DataFrame([
        {
            'Split_Type': 'Old Random 80/20 Split',
            'Accuracy': round(acc_rand, 4),
            'Macro_F1': round(f1_rand, 4),
            'Test_Rows': len(df_te_rand),
            'Duplicate_Feature_Rows_In_Test': dups_in_test_rand,
            'Duplicate_Test_Percentage': round(dups_pct_rand, 2),
            'Methodology_Note': 'Random shuffle leaks consecutive counter snapshots into test'
        },
        {
            'Split_Type': 'New Temporal 70/30 Split (200-row gap)',
            'Accuracy': round(acc_temp, 4),
            'Macro_F1': round(f1_temp, 4),
            'Test_Rows': len(df_te_temp),
            'Duplicate_Feature_Rows_In_Test': dups_in_test_temp,
            'Duplicate_Test_Percentage': round(dups_pct_temp, 2),
            'Methodology_Note': 'Strictly chronological by port_duration_sec with purge gap'
        }
    ])
    
    print(comp_df.to_string(index=False), flush=True)
    return comp_df, rf_temp


def run_diagnostic_ablation(train_df, test_df):
    """
    Diagnostic 2: Feature Ablation study.
    Drops table_active_count and port_tx_bytes, retrains on temporal split.
    """
    print("\n" + "=" * 80, flush=True)
    print("STEP 5: Diagnostic 2 - Feature Ablation (Drop table_active_count & port_tx_bytes)", flush=True)
    print("=" * 80, flush=True)
    
    ablated_features = [f for f in FIXED_9_FEATURES if f not in ['table_active_count', 'port_tx_bytes']]
    print(f"Remaining 7 features: {ablated_features}", flush=True)
    
    X_train_abl = train_df[ablated_features].values
    y_train = train_df['type'].values
    X_test_abl = test_df[ablated_features].values
    y_test = test_df['type'].values
    
    # Evaluate Random Forest, Decision Tree, and LightGBM
    abl_models = {
        'Random Forest (Ablated 7)': RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1),
        'Decision Tree (Ablated 7)': DecisionTreeClassifier(random_state=RANDOM_STATE),
        'LightGBM (Ablated 7)': lgb.LGBMClassifier(random_state=RANDOM_STATE, n_jobs=-1, verbose=-1)
    }
    
    abl_results = []
    for name, model in abl_models.items():
        t0 = time.time()
        model.fit(X_train_abl, y_train)
        y_pred = model.predict(X_test_abl)
        acc = accuracy_score(y_test, y_pred)
        f1_mac = f1_score(y_test, y_pred, average='macro', zero_division=0)
        f1_w = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        abl_results.append({
            'Model_Configuration': name,
            'Features_Used': '7 features (No table_active_count, No port_tx_bytes)',
            'Accuracy': round(acc, 4),
            'Macro_F1': round(f1_mac, 4),
            'Weighted_F1': round(f1_w, 4),
            'Fit_Time_Sec': round(time.time() - t0, 2)
        })
        print(f"  {name:<28}: Acc = {acc*100:6.2f}% | Macro F1 = {f1_mac:6.4f}", flush=True)
        
    return pd.DataFrame(abl_results)


def run_diagnostic_unseen_normal(rf_model, data_folder='Archieve'):
    """
    Diagnostic 4: Classifies 100% of rows of normal_iperf.csv and normal_internet1/2/3.csv
    using the model trained on normal_ditg.csv only.
    Reports percent classified as Normal and breakdown of attack false positives.
    """
    print("\n" + "=" * 80, flush=True)
    print("STEP 6: Diagnostic 4 - Generalization to Unseen Normal Traffic", flush=True)
    print("=" * 80, flush=True)
    
    unseen_files = [
        ('normal_iperf.csv', 'Normal (iPerf load generator)'),
        ('normal_internet1.csv', 'Normal (Internet trace 1)'),
        ('normal_internet2.csv', 'Normal (Internet trace 2)'),
        ('normal_internet3.csv', 'Normal (Internet trace 3)')
    ]
    
    rows = []
    for fname, desc in unseen_files:
        fpath = os.path.join(data_folder, fname)
        if not os.path.exists(fpath):
            continue
        df = pd.read_csv(fpath, names=ALL_COLUMNS, low_memory=False)
        for col in FIXED_9_FEATURES:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        df = df.dropna(subset=FIXED_9_FEATURES)
        
        preds = rf_model.predict(df[FIXED_9_FEATURES].values)
        pred_labels = [ID_TO_CLASS[p] for p in preds]
        n_total = len(pred_labels)
        
        counts = pd.Series(pred_labels).value_counts()
        normal_count = counts.get('Normal', 0)
        normal_pct = (normal_count / n_total) * 100
        
        # Get top false positive attack classes
        non_normal_counts = counts.drop('Normal', errors='ignore')
        top_false_positives = ", ".join([f"{cls}: {cnt} ({cnt/n_total*100:.1f}%)" for cls, cnt in non_normal_counts.head(3).items()])
        
        rows.append({
            'File': fname,
            'Description': desc,
            'Total_Rows': n_total,
            'Classified_As_Normal_Count': normal_count,
            'Percent_Normal (True Negative Rate)': round(normal_pct, 2),
            'Top_False_Positive_Attacks': top_false_positives if len(non_normal_counts) > 0 else 'None'
        })
        print(f"  {fname:<24} ({n_total:<6} rows) -> Classified as Normal: {normal_pct:6.2f}% | "
              f"False Positives: {top_false_positives}", flush=True)
        
    return pd.DataFrame(rows)


def run_diagnostic_unseen_attack(rf_model, data_folder='Archieve'):
    """
    Diagnostic 5: Classifies ddos_attack_scapy_new.csv and reports raw label distribution.
    Does not assume it belongs to any class.
    """
    print("\n" + "=" * 80, flush=True)
    print("STEP 7: Diagnostic 5 - Unseen Attack Traffic Evaluation (Scapy DDoS)", flush=True)
    print("=" * 80, flush=True)
    
    fpath = os.path.join(data_folder, 'ddos_attack_scapy_new.csv')
    df = pd.read_csv(fpath, names=ALL_COLUMNS, low_memory=False)
    for col in FIXED_9_FEATURES:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df = df.dropna(subset=FIXED_9_FEATURES)
    
    preds = rf_model.predict(df[FIXED_9_FEATURES].values)
    pred_labels = [ID_TO_CLASS[p] for p in preds]
    n_total = len(pred_labels)
    
    counts = pd.Series(pred_labels).value_counts()
    
    rows = []
    print(f"  Total Rows: {n_total} in ddos_attack_scapy_new.csv", flush=True)
    for label, count in counts.items():
        pct = (count / n_total) * 100
        rows.append({
            'Assigned_Class': label,
            'Predicted_Count': count,
            'Percentage': round(pct, 2)
        })
        print(f"    -> {label:<15}: {count:<6} ({pct:6.2f}%)", flush=True)
        
    return pd.DataFrame(rows)


def run_diagnostic_feature_drift(train_df, test_df):
    """
    Diagnostic 6 (Addition 2): For each of the 9 features and each class,
    reports train min/max and test min/max, and the percent of test rows
    where ANY feature exceeds the train maximum.
    """
    print("\n" + "=" * 80, flush=True)
    print("STEP 8: Diagnostic 6 - Feature Drift & Range Invariant Analysis (Addition 2)", flush=True)
    print("=" * 80, flush=True)
    
    drift_rows = []
    class_exceed_summary = []
    
    for cname in CLASS_NAMES:
        cid = CLASS_TO_ID[cname]
        tr_c = train_df[train_df['type'] == cid]
        te_c = test_df[test_df['type'] == cid]
        
        if len(tr_c) == 0 or len(te_c) == 0:
            continue
            
        exceeds_any_feature = np.zeros(len(te_c), dtype=bool)
        
        for feat in FIXED_9_FEATURES:
            tr_min = float(tr_c[feat].min())
            tr_max = float(tr_c[feat].max())
            te_min = float(te_c[feat].min())
            te_max = float(te_c[feat].max())
            
            # Rows in test where this specific feature > train max
            feat_exceed = (te_c[feat] > tr_max).sum()
            feat_exceed_pct = (feat_exceed / len(te_c)) * 100
            
            exceeds_any_feature = exceeds_any_feature | (te_c[feat].values > tr_max)
            
            drift_rows.append({
                'Class': cname,
                'Feature': feat,
                'Train_Min': tr_min,
                'Train_Max': tr_max,
                'Test_Min': te_min,
                'Test_Max': te_max,
                'Test_Exceeds_Train_Max_Count': feat_exceed,
                'Test_Exceeds_Train_Max_Pct': round(feat_exceed_pct, 2)
            })
            
        total_exceed_rows = exceeds_any_feature.sum()
        total_exceed_pct = (total_exceed_rows / len(te_c)) * 100
        
        class_exceed_summary.append({
            'Class': cname,
            'Test_Rows': len(te_c),
            'Rows_Exceeding_Any_Train_Max': total_exceed_rows,
            'Percent_Exceeding_Any_Train_Max': round(total_exceed_pct, 2)
        })
        
        print(f"  Class {cname:<13} ({len(te_c):<5} test rows): {total_exceed_pct:6.2f}% rows exceed train maximum on >=1 feature", flush=True)
        
    drift_df = pd.DataFrame(drift_rows)
    return drift_df, pd.DataFrame(class_exceed_summary)


# ---------------------------------------------------------
# TASK C: Artifact Generation & Findings
# ---------------------------------------------------------

def export_artifacts(metrics_df, per_class_df, cms, leakage_df, unseen_normal_df, unseen_attack_df, drift_df, class_drift_summary):
    """
    Saves all metrics, tables, and confusion matrix figure into results/.
    """
    print("\n" + "=" * 80, flush=True)
    print("STEP 9: Exporting Artifacts to results/ Directory", flush=True)
    print("=" * 80, flush=True)
    
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    # 1. metrics.csv
    metrics_path = os.path.join(RESULTS_DIR, 'metrics.csv')
    metrics_df.to_csv(metrics_path, index=False)
    print(f"  Saved: {metrics_path}", flush=True)
    
    # 2. per_class_report.csv
    per_class_path = os.path.join(RESULTS_DIR, 'per_class_report.csv')
    per_class_df.to_csv(per_class_path, index=False)
    print(f"  Saved: {per_class_path}", flush=True)
    
    # 3. confusion_matrix.png (Random Forest best model)
    rf_cm = cms['Random Forest']
    plt.figure(figsize=(10, 8))
    sns.heatmap(
        rf_cm, annot=True, fmt='d', cmap='Blues',
        xticklabels=CLASS_NAMES, yticklabels=CLASS_NAMES
    )
    plt.title('HealthGuard AI — Honest Temporal Evaluation 9x9 Confusion Matrix\n(Random Forest, 70/30 Temporal Split with 200-row Purge Gap)')
    plt.xlabel('Predicted Class')
    plt.ylabel('True Class')
    plt.tight_layout()
    cm_path = os.path.join(RESULTS_DIR, 'confusion_matrix.png')
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"  Saved: {cm_path}", flush=True)
    
    # 4. leakage_comparison.csv
    leakage_path = os.path.join(RESULTS_DIR, 'leakage_comparison.csv')
    leakage_df.to_csv(leakage_path, index=False)
    print(f"  Saved: {leakage_path}", flush=True)
    
    # 5. unseen_traffic.csv
    unseen_path = os.path.join(RESULTS_DIR, 'unseen_traffic.csv')
    # Combine normal and attack into one structured table or save both
    unseen_normal_df['Traffic_Type'] = 'Unseen Normal'
    unseen_attack_df['Traffic_Type'] = 'Unseen Attack (Scapy)'
    unseen_normal_df.to_csv(unseen_path, index=False)
    unseen_attack_df.to_csv(os.path.join(RESULTS_DIR, 'unseen_attack_scapy.csv'), index=False)
    print(f"  Saved: {unseen_path} & results/unseen_attack_scapy.csv", flush=True)
    
    # 6. feature_drift.csv
    drift_path = os.path.join(RESULTS_DIR, 'feature_drift.csv')
    drift_df.to_csv(drift_path, index=False)
    class_drift_path = os.path.join(RESULTS_DIR, 'class_drift_summary.csv')
    class_drift_summary.to_csv(class_drift_path, index=False)
    print(f"  Saved: {drift_path} & {class_drift_path}", flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="HealthGuard AI Honest ML Evaluation Pipeline")
    parser.add_argument('--verify-only', action='store_true', help="Run pre-flight chronology check only")
    parser.add_argument('--skip-tuning', action='store_true', help="Use default parameters without grid search")
    args = parser.parse_args()
    
    t_start = time.time()
    
    # Step 1: Pre-flight chronology check
    chrono_df = verify_chronological_ordering()
    if args.verify_only:
        sys.exit(0)
        
    # Step 2: Temporal partition
    train_df, test_df, summary_df = load_temporal_split(train_ratio=0.70, gap_rows=200)
    
    # Step 3: Multi-model evaluation
    metrics_df, per_class_df, cms, best_models = evaluate_models_temporal(train_df, test_df)
    
    # Step 4: Diagnostics 1 & 3 (Random vs Temporal & Duplicates)
    leakage_df, rf_model = run_diagnostic_random_vs_temporal(train_df, test_df)
    
    # Step 5: Diagnostic 2 (Feature Ablation)
    ablation_df = run_diagnostic_ablation(train_df, test_df)
    
    # Step 6: Diagnostic 4 (Unseen Normal Generalization)
    unseen_normal_df = run_diagnostic_unseen_normal(rf_model)
    
    # Step 7: Diagnostic 5 (Unseen Attack Generalization)
    unseen_attack_df = run_diagnostic_unseen_attack(rf_model)
    
    # Step 8: Diagnostic 6 (Feature Drift & Invariant Ranges)
    drift_df, class_drift_summary = run_diagnostic_feature_drift(train_df, test_df)
    
    # Step 9: Export Artifacts
    export_artifacts(
        metrics_df, per_class_df, cms, leakage_df,
        unseen_normal_df, unseen_attack_df, drift_df, class_drift_summary
    )
    
    print("\n" + "=" * 80, flush=True)
    print(f"ALL EVALUATIONS & DIAGNOSTICS COMPLETED IN {time.time() - t_start:.2f} SECONDS", flush=True)
    print("=" * 80, flush=True)
