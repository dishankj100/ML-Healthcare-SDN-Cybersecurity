"""
STEP 3 (part B): train and evaluate R1, R2, and F9-on-R2-rows.

Same 8 models, same train-only TimeSeriesSplit tuning, same scoring as
evaluate_honest.py. Temporal split: first 70%, 200-row gap, last 30%.

Outputs under results/rate_features/
"""
import os, time, json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import TimeSeriesSplit, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             classification_report, confusion_matrix)
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
import xgboost as xgb
import lightgbm as lgb

RANDOM_STATE = 42
OUT = 'results/rate_features'
os.makedirs(OUT, exist_ok=True)

ALL_COLUMNS = ['src','dst','table_id','ip_bytes','ip_packet','ip_duration','in_port','dl_dst','port_bytes',
 'port_packet','port_flow_count','table_active_count','table_lookup_count','table_matched_count',
 'port_rx_packets','port_tx_packets','port_rx_bytes','port_tx_bytes','port_rx_dropped','port_tx_dropped',
 'port_rx_errors','port_tx_errors','port_rx_frame_err','port_rx_over_err','port_crc_err',
 'port_collisions','port_duration_sec']

F9 = ['ip_bytes','ip_packet','port_bytes','port_packet','port_flow_count',
      'table_active_count','port_rx_packets','port_rx_bytes','port_tx_bytes']

R1_COLS = ['ip_bytes','ip_packet','ip_bytes_per_packet',
           'port_rx_bytes_rate','port_tx_bytes_rate','port_rx_packets_rate',
           'port_rx_bytes_per_packet','port_flow_count','table_active_count']

R2_COLS = ['rx_bytes_rate','tx_bytes_rate','rx_packets_rate',
           'delta_bytes_per_packet','port_flow_count','table_active_count']

TC = [('Normal','Archieve/normal_ditg.csv'),('BruteForce','Archieve/attack_bruteforce.csv'),
 ('CMD','Archieve/attack_cmd.csv'),('TCPDDOS','Archieve/attack_ddos_tcp.csv'),
 ('UDPDDOS','Archieve/attack_ddos_udp.csv'),('Probe','Archieve/attack_os_port_scan.csv'),
 ('Smaba','Archieve/attack_samba.csv'),('SQLInjection','Archieve/attack_sql_injection.csv'),
 ('VNC','Archieve/attack_vnc.csv')]
CLASS_NAMES = sorted([c[0] for c in TC])
CLASS_TO_ID = {n:i for i,n in enumerate(CLASS_NAMES)}
ID_TO_CLASS = {i:n for n,i in CLASS_TO_ID.items()}


def load_clean(fp):
    df = pd.read_csv(fp, names=ALL_COLUMNS, low_memory=False)
    for c in F9 + ['port_duration_sec','ip_duration']:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    return df.dropna(subset=F9).reset_index(drop=True)


def build_r1(df):
    out = pd.DataFrame(index=df.index)
    out['ip_bytes'] = df['ip_bytes'].astype(float)
    out['ip_packet'] = df['ip_packet'].astype(float)
    out['ip_bytes_per_packet'] = np.where(df['ip_packet'] > 0,
        df['ip_bytes'] / df['ip_packet'].replace(0, np.nan), 0.0)
    pds = df['port_duration_sec'].astype(float)
    out['port_rx_bytes_rate'] = df['port_rx_bytes'] / pds
    out['port_tx_bytes_rate'] = df['port_tx_bytes'] / pds
    out['port_rx_packets_rate'] = df['port_rx_packets'] / pds
    out['port_rx_bytes_per_packet'] = np.where(df['port_rx_packets'] > 0,
        df['port_rx_bytes'] / df['port_rx_packets'].replace(0, np.nan), 0.0)
    out['port_flow_count'] = df['port_flow_count'].astype(float)
    out['table_active_count'] = df['table_active_count'].astype(float)
    return out


def build_r2(df):
    d = df
    g = d.groupby(['src','dst','in_port'], sort=False)
    prx_b = g['port_rx_bytes'].shift(1); ptx_b = g['port_tx_bytes'].shift(1)
    prx_p = g['port_rx_packets'].shift(1); pt = g['port_duration_sec'].shift(1)
    dt = d['port_duration_sec'] - pt
    drx_b = d['port_rx_bytes'] - prx_b
    dtx_b = d['port_tx_bytes'] - ptx_b
    drx_p = d['port_rx_packets'] - prx_p
    first = prx_b.isna()
    valid = (~first) & (dt > 0) & (drx_b >= 0) & (dtx_b >= 0) & (drx_p >= 0)
    out = pd.DataFrame(index=df.index)
    out['rx_bytes_rate'] = np.where(valid, drx_b / dt.replace(0, np.nan), np.nan)
    out['tx_bytes_rate'] = np.where(valid, dtx_b / dt.replace(0, np.nan), np.nan)
    out['rx_packets_rate'] = np.where(valid, drx_p / dt.replace(0, np.nan), np.nan)
    out['delta_bytes_per_packet'] = np.where(valid & (drx_p > 0),
        drx_b / drx_p.replace(0, np.nan), 0.0)
    out['port_flow_count'] = df['port_flow_count'].astype(float)
    out['table_active_count'] = df['table_active_count'].astype(float)
    return out, valid.values


def temporal_masks(n, train_ratio=0.70, gap_rows=200):
    train_end = int(np.floor(n * train_ratio))
    test_start = train_end + gap_rows
    return train_end, test_start


def get_model_specs():
    return {
        'Decision Tree': {'estimator': DecisionTreeClassifier(random_state=RANDOM_STATE),
            'param_grid': {'max_depth':[5,10,15,None],'min_samples_split':[2,10]}},
        'Random Forest': {'estimator': RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1),
            'param_grid': {'max_depth':[10,15,None],'min_samples_split':[2,5]}},
        'KNN': {'estimator': Pipeline([('scaler',StandardScaler()),('knn',KNeighborsClassifier(n_jobs=-1))]),
            'param_grid': {'knn__n_neighbors':[3,5,7]}},
        'Naive Bayes': {'estimator': GaussianNB(), 'param_grid': {'var_smoothing':[1e-9,1e-8,1e-7]}},
        'Logistic Regression': {'estimator': Pipeline([('scaler',StandardScaler()),
            ('clf',LogisticRegression(max_iter=500, random_state=RANDOM_STATE))]),
            'param_grid': {'clf__C':[0.1,1.0,10.0]}},
        'AdaBoost': {'estimator': AdaBoostClassifier(random_state=RANDOM_STATE),
            'param_grid': {'n_estimators':[50,100],'learning_rate':[0.1,1.0]}},
        'XGBoost': {'estimator': xgb.XGBClassifier(random_state=RANDOM_STATE, n_jobs=-1, eval_metric='mlogloss'),
            'param_grid': {'n_estimators':[50,100],'max_depth':[4,6],'learning_rate':[0.1,0.2]}},
        'LightGBM': {'estimator': lgb.LGBMClassifier(random_state=RANDOM_STATE, n_jobs=-1, verbose=-1),
            'param_grid': {'n_estimators':[50,100],'num_leaves':[31,63],'learning_rate':[0.1,0.2]}},
    }


def evaluate(X_train, y_train, X_test, y_test, tag, cv_splits=3):
    tscv = TimeSeriesSplit(n_splits=cv_splits)
    metrics, per_class, cms, fitted = [], [], {}, {}
    for name, spec in get_model_specs().items():
        print(f"  [{tag}] {name}...", flush=True)
        t0 = time.time()
        grid = GridSearchCV(spec['estimator'], spec['param_grid'], cv=tscv,
                            scoring='f1_macro',
                            n_jobs=-1 if name not in ['Random Forest','KNN','XGBoost','LightGBM'] else 1)
        grid.fit(X_train, y_train)
        be = grid.best_estimator_; fitted[name] = be
        y_pred = be.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        metrics.append({'Model':name,'CV_f1_macro':round(grid.best_score_,4),
            'Test_Accuracy':round(acc,4),
            'Macro_Precision':round(precision_score(y_test,y_pred,average='macro',zero_division=0),4),
            'Macro_Recall':round(recall_score(y_test,y_pred,average='macro',zero_division=0),4),
            'Macro_F1':round(f1_score(y_test,y_pred,average='macro',zero_division=0),4),
            'Weighted_F1':round(f1_score(y_test,y_pred,average='weighted',zero_division=0),4),
            'Best_Params':str(grid.best_params_),'Tune_Time_Sec':round(time.time()-t0,2)})
        rep = classification_report(y_test, y_pred, target_names=CLASS_NAMES,
                                    output_dict=True, zero_division=0)
        for cn in CLASS_NAMES:
            per_class.append({'Model':name,'Class':cn,
                'Precision':round(rep[cn]['precision'],4),'Recall':round(rep[cn]['recall'],4),
                'F1_Score':round(rep[cn]['f1-score'],4),'Support':int(rep[cn]['support'])})
        cms[name] = confusion_matrix(y_test, y_pred)
        print(f"    -> acc={acc:.4f} macroF1={metrics[-1]['Macro_F1']:.4f}", flush=True)
    return pd.DataFrame(metrics), pd.DataFrame(per_class), cms, fitted


def feature_drift(X_train, X_test, y_test, cols, tag):
    rows = []
    for cid in sorted(set(y_test)):
        m = y_test == cid
        for j, c in enumerate(cols):
            tr_max = np.nanmax(X_train[:, j])
            te = X_test[m, j]
            exc = int((te > tr_max).sum())
            rows.append({'Feature_Set':tag,'Class':ID_TO_CLASS[cid],'Feature':c,
                'Train_Max':float(tr_max),'Test_Max':float(np.nanmax(te)),
                'Test_Exceeds_Train_Max_Count':exc,
                'Test_Exceeds_Train_Max_Pct':round(exc/len(te)*100,2)})
    return pd.DataFrame(rows)


def main():
    print("="*78); print("Building R1 / R2 / F9-on-R2-rows datasets"); print("="*78)
    r1_tr, r1_te, r2_tr, r2_te, f9_tr, f9_te = [], [], [], [], [], []
    y_tr_r1, y_te_r1, y_tr_r2, y_te_r2 = [], [], [], []

    for cname, fp in TC:
        df = load_clean(fp)
        n = len(df)
        te_end, ts_start = temporal_masks(n)
        lab = CLASS_TO_ID[cname]

        R1 = build_r1(df)
        R2, valid = build_r2(df)

        tr_idx = np.arange(0, te_end)
        te_idx = np.arange(ts_start, n)

        # R1: all rows
        r1_tr.append(R1.iloc[tr_idx]); y_tr_r1.append(np.full(len(tr_idx), lab))
        r1_te.append(R1.iloc[te_idx]); y_te_r1.append(np.full(len(te_idx), lab))

        # R2: retained rows only
        tr_v = tr_idx[valid[tr_idx]]
        te_v = te_idx[valid[te_idx]]
        r2_tr.append(R2.iloc[tr_v]); y_tr_r2.append(np.full(len(tr_v), lab))
        r2_te.append(R2.iloc[te_v]); y_te_r2.append(np.full(len(te_v), lab))

        # F9 on exactly the R2 retained rows
        f9_tr.append(df.iloc[tr_v][F9]); f9_te.append(df.iloc[te_v][F9])

        print(f"  {cname:<13} R1 train={len(tr_idx):<7} test={len(te_idx):<7} | "
              f"R2 train={len(tr_v):<7} test={len(te_v):<7}")

    def stack(parts, cols=None):
        d = pd.concat(parts, ignore_index=True)
        return d[cols].values.astype(float) if cols else d.values.astype(float)

    Xr1_tr = stack(r1_tr, R1_COLS); Xr1_te = stack(r1_te, R1_COLS)
    Xr2_tr = stack(r2_tr, R2_COLS); Xr2_te = stack(r2_te, R2_COLS)
    Xf9_tr = stack(f9_tr, F9);      Xf9_te = stack(f9_te, F9)
    ytr1 = np.concatenate(y_tr_r1); yte1 = np.concatenate(y_te_r1)
    ytr2 = np.concatenate(y_tr_r2); yte2 = np.concatenate(y_te_r2)

    print(f"\nR1: train={Xr1_tr.shape} test={Xr1_te.shape}")
    print(f"R2: train={Xr2_tr.shape} test={Xr2_te.shape}")
    print(f"F9-on-R2-rows: train={Xf9_tr.shape} test={Xf9_te.shape}")

    drift_all = []
    results = {}

    for tag, Xtr, ytr, Xte, yte, cols in [
        ('R1', Xr1_tr, ytr1, Xr1_te, yte1, R1_COLS),
        ('R2', Xr2_tr, ytr2, Xr2_te, yte2, R2_COLS),
        ('F9_on_R2_rows', Xf9_tr, ytr2, Xf9_te, yte2, F9),
    ]:
        print("\n" + "="*78); print(f"EVALUATING {tag}"); print("="*78)
        m, pc, cms, fitted = evaluate(Xtr, ytr, Xte, yte, tag)
        m.to_csv(os.path.join(OUT, f'metrics_{tag}.csv'), index=False)
        pc.to_csv(os.path.join(OUT, f'per_class_report_{tag}.csv'), index=False)
        drift_all.append(feature_drift(Xtr, Xte, yte, cols, tag))

        best = m.loc[m['Test_Accuracy'].idxmax(), 'Model']
        cm = cms[best]
        fig, ax = plt.subplots(figsize=(10,8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                    xticklabels=CLASS_NAMES, yticklabels=CLASS_NAMES, ax=ax)
        ax.set_xlabel('Predicted'); ax.set_ylabel('Actual')
        ax.set_title(f'{tag} - {best} (acc={m["Test_Accuracy"].max():.4f})')
        plt.tight_layout()
        plt.savefig(os.path.join(OUT, f'confusion_matrix_{tag}.png'), dpi=100)
        plt.close()
        results[tag] = (m, fitted)
        print(f"\n{tag} metrics:\n{m.to_string(index=False)}")

    pd.concat(drift_all, ignore_index=True).to_csv(
        os.path.join(OUT, 'feature_drift_new_features.csv'), index=False)
    print(f"\nSaved metrics, per-class, confusion matrices, drift to {OUT}/")

    # ---------------- unseen traffic ----------------
    print("\n" + "="*78); print("UNSEEN TRAFFIC (all 8 models)"); print("="*78)
    UNSEEN = [('normal_iperf.csv','Unseen Normal'),('normal_internet1.csv','Unseen Normal'),
              ('normal_internet2.csv','Unseen Normal'),('normal_internet3.csv','Unseen Normal'),
              ('ddos_attack_scapy_new.csv','Unseen Attack (Scapy DDoS)')]
    unseen_rows = []
    for fname, ttype in UNSEEN:
        df = load_clean(os.path.join('Archieve', fname))
        R1u = build_r1(df)
        R2u, vu = build_r2(df)
        for tag, cols, frame, mask in [('R1', R1_COLS, R1u, None), ('R2', R2_COLS, R2u, vu)]:
            X = frame[cols].values.astype(float)
            if mask is not None:
                X = X[mask]
            for name, model in results[tag][1].items():
                preds = model.predict(X)
                labels = pd.Series([ID_TO_CLASS[p] for p in preds])
                cnt = labels.value_counts(); n = len(labels)
                unseen_rows.append({'Feature_Set':tag,'Model':name,'File':fname,
                    'Traffic_Type':ttype,'Rows_Scored':n,
                    'Classified_As_Normal_Count':int(cnt.get('Normal',0)),
                    'Percent_Normal':round(int(cnt.get('Normal',0))/n*100,2),
                    'Label_Distribution':", ".join(f"{c}: {int(v)} ({v/n*100:.2f}%)" for c,v in cnt.items())})
        print(f"  scored {fname} ({len(df)} rows)", flush=True)

    un = pd.DataFrame(unseen_rows)
    un.to_csv(os.path.join(OUT, 'unseen_traffic_all_models.csv'), index=False)
    print(f"\nSaved: {OUT}/unseen_traffic_all_models.csv ({len(un)} rows)")

    print("\n" + "="*78); print("PERCENT NORMAL BY MODEL (R1 vs R2)"); print("="*78)
    for tag in ['R1','R2']:
        sub = un[un['Feature_Set']==tag]
        piv = sub.pivot_table(index='File', columns='Model', values='Percent_Normal', sort=False)
        print(f"\n--- {tag} ---"); print(piv.to_string())

    print("\n" + "="*78); print("SCAPY LABEL DISTRIBUTION"); print("="*78)
    for tag in ['R1','R2']:
        sub = un[(un['Feature_Set']==tag) & (un['File']=='ddos_attack_scapy_new.csv')]
        print(f"\n--- {tag} ---")
        for _, r in sub.iterrows():
            print(f"  {r['Model']:<22} {r['Label_Distribution']}")

    print("\nDONE")


if __name__ == '__main__':
    main()
