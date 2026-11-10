"""
Final cleanup: (1) LogReg with max_iter=5000 + log1p on rate features,
               (2) validation-block tuning replacing CV for R1/R2.

Validation block = last 15% of each class's TRAIN timeline, tuned on first 85%.
Every class appears in both parts because each class's train slice is contiguous.

Writes results/rate_features/logreg_log1p.csv
       results/rate_features/validation_block_metrics_{R1,R2}.csv
       results/rate_features/validation_block_selection.csv
"""
import os, time
import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
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

# rate / ratio features that get log1p; gauges and raw counts are left alone
R1_LOG = ['ip_bytes_per_packet','port_rx_bytes_rate','port_tx_bytes_rate',
          'port_rx_packets_rate','port_rx_bytes_per_packet']
R2_LOG = ['rx_bytes_rate','tx_bytes_rate','rx_packets_rate','delta_bytes_per_packet']

TC = [('Normal','Archieve/normal_ditg.csv'),('BruteForce','Archieve/attack_bruteforce.csv'),
 ('CMD','Archieve/attack_cmd.csv'),('TCPDDOS','Archieve/attack_ddos_tcp.csv'),
 ('UDPDDOS','Archieve/attack_ddos_udp.csv'),('Probe','Archieve/attack_os_port_scan.csv'),
 ('Smaba','Archieve/attack_samba.csv'),('SQLInjection','Archieve/attack_sql_injection.csv'),
 ('VNC','Archieve/attack_vnc.csv')]
CLASS_NAMES = sorted([c[0] for c in TC])
CLASS_TO_ID = {n:i for i,n in enumerate(CLASS_NAMES)}


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
    g = df.groupby(['src','dst','in_port'], sort=False)
    prx_b = g['port_rx_bytes'].shift(1); ptx_b = g['port_tx_bytes'].shift(1)
    prx_p = g['port_rx_packets'].shift(1); pt = g['port_duration_sec'].shift(1)
    dt = df['port_duration_sec'] - pt
    drx_b = df['port_rx_bytes'] - prx_b
    dtx_b = df['port_tx_bytes'] - ptx_b
    drx_p = df['port_rx_packets'] - prx_p
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


def build_all():
    """Returns train/test frames for R1 and R2, plus per-class train row counts."""
    r1_tr, r1_te, r2_tr, r2_te = [], [], [], []
    y1_tr, y1_te, y2_tr, y2_te = [], [], [], []
    for cname, fp in TC:
        df = load_clean(fp)
        n = len(df)
        train_end = int(np.floor(n * 0.70))
        test_start = train_end + 200
        lab = CLASS_TO_ID[cname]

        R1 = build_r1(df)
        R2, valid = build_r2(df)

        tr_idx = np.arange(0, train_end)
        te_idx = np.arange(test_start, n)

        r1_tr.append(R1.iloc[tr_idx]); y1_tr.append(np.full(len(tr_idx), lab))
        r1_te.append(R1.iloc[te_idx]); y1_te.append(np.full(len(te_idx), lab))

        tr_v = tr_idx[valid[tr_idx]]
        te_v = te_idx[valid[te_idx]]
        r2_tr.append(R2.iloc[tr_v]); y2_tr.append(np.full(len(tr_v), lab))
        r2_te.append(R2.iloc[te_v]); y2_te.append(np.full(len(te_v), lab))

    def pack(parts, cols):
        return pd.concat(parts, ignore_index=True)[cols].values.astype(float)

    return {
        'R1': (pack(r1_tr, R1_COLS), np.concatenate(y1_tr),
               pack(r1_te, R1_COLS), np.concatenate(y1_te), R1_COLS, R1_LOG),
        'R2': (pack(r2_tr, R2_COLS), np.concatenate(y2_tr),
               pack(r2_te, R2_COLS), np.concatenate(y2_te), R2_COLS, R2_LOG),
    }


def apply_log1p(X, cols, log_cols):
    X = X.copy()
    idx = [cols.index(c) for c in log_cols]
    X[:, idx] = np.log1p(np.clip(X[:, idx], 0, None))
    return X


def metrics_row(name, y_true, y_pred):
    return {
        'Model': name,
        'Test_Accuracy': round(float(accuracy_score(y_true, y_pred)), 4),
        'Macro_Precision': round(float(precision_score(y_true, y_pred, average='macro', zero_division=0)), 4),
        'Macro_Recall': round(float(recall_score(y_true, y_pred, average='macro', zero_division=0)), 4),
        'Macro_F1': round(float(f1_score(y_true, y_pred, average='macro', zero_division=0)), 4),
        'Weighted_F1': round(float(f1_score(y_true, y_pred, average='weighted', zero_division=0)), 4),
    }


# ---------------- TASK 1 ----------------
def task1(data):
    print("=" * 78)
    print("TASK 1: Logistic Regression, max_iter=5000, log1p on rate features")
    print("=" * 78)
    rows = []
    for tag in ['R1', 'R2']:
        Xtr, ytr, Xte, yte, cols, log_cols = data[tag]
        Xtr_l = apply_log1p(Xtr, cols, log_cols)
        Xte_l = apply_log1p(Xte, cols, log_cols)
        print(f"\n[{tag}] log1p applied to: {log_cols}")
        print(f"[{tag}] left untransformed: {[c for c in cols if c not in log_cols]}")

        for variant, A, B in [('raw (no log1p)', Xtr, Xte), ('log1p rates', Xtr_l, Xte_l)]:
            pipe = Pipeline([('scaler', StandardScaler()),
                             ('clf', LogisticRegression(C=1.0, max_iter=5000,
                                                        random_state=RANDOM_STATE))])
            pipe.fit(A, ytr)
            clf = pipe.named_steps['clf']
            n_iter = int(np.max(clf.n_iter_))
            converged = n_iter < 5000
            pred = pipe.predict(B)
            r = metrics_row(f'Logistic Regression {tag} {variant}', yte, pred)
            r['Feature_Set'] = tag
            r['Variant'] = variant
            r['Max_Iter'] = 5000
            r['Iterations_Used'] = n_iter
            r['Converged'] = bool(converged)
            rows.append(r)
            print(f"  {variant:<16} converged={converged} (n_iter={n_iter})  "
                  f"acc={r['Test_Accuracy']:.4f}  macroF1={r['Macro_F1']:.4f}")

    out = pd.DataFrame(rows)[['Feature_Set','Variant','Max_Iter','Iterations_Used','Converged',
                              'Test_Accuracy','Macro_Precision','Macro_Recall','Macro_F1','Weighted_F1']]
    out.to_csv(os.path.join(OUT, 'logreg_log1p.csv'), index=False)
    print("\n" + out.to_string(index=False))
    print(f"\nSaved: {OUT}/logreg_log1p.csv")
    return out


# ---------------- TASK 2 ----------------
def get_specs():
    return {
        'Decision Tree': {'est': DecisionTreeClassifier(random_state=RANDOM_STATE),
            'grid': {'max_depth':[5,10,15,None],'min_samples_split':[2,10]}},
        'Random Forest': {'est': RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1),
            'grid': {'max_depth':[10,15,None],'min_samples_split':[2,5]}},
        'KNN': {'est': Pipeline([('scaler',StandardScaler()),('knn',KNeighborsClassifier(n_jobs=-1))]),
            'grid': {'knn__n_neighbors':[3,5,7]}},
        'Naive Bayes': {'est': GaussianNB(), 'grid': {'var_smoothing':[1e-9,1e-8,1e-7]}},
        'Logistic Regression': {'est': Pipeline([('scaler',StandardScaler()),
            ('clf',LogisticRegression(max_iter=5000, random_state=RANDOM_STATE))]),
            'grid': {'clf__C':[0.1,1.0,10.0]}},
        'AdaBoost': {'est': AdaBoostClassifier(random_state=RANDOM_STATE),
            'grid': {'n_estimators':[50,100],'learning_rate':[0.1,1.0]}},
        'XGBoost': {'est': xgb.XGBClassifier(random_state=RANDOM_STATE, n_jobs=-1, eval_metric='mlogloss'),
            'grid': {'n_estimators':[50,100],'max_depth':[4,6],'learning_rate':[0.1,0.2]}},
        'LightGBM': {'est': lgb.LGBMClassifier(random_state=RANDOM_STATE, n_jobs=-1, verbose=-1),
            'grid': {'n_estimators':[50,100],'num_leaves':[31,63],'learning_rate':[0.1,0.2]}},
    }


def task2(data):
    print("\n" + "=" * 78)
    print("TASK 2: Validation-block tuning (last 15% of each class's TRAIN timeline)")
    print("=" * 78)
    import itertools

    all_rows, sel_rows = [], []
    for tag in ['R1', 'R2']:
        Xtr, ytr, Xte, yte, cols, log_cols = data[tag]
        Xtr_l = apply_log1p(Xtr, cols, log_cols)
        Xte_l = apply_log1p(Xte, cols, log_cols)

        # per-class split of the TRAIN block: first 85% tune, last 15% validate
        tune_idx, val_idx = [], []
        for cid in sorted(set(ytr)):
            idx = np.flatnonzero(ytr == cid)
            cut = int(np.floor(len(idx) * 0.85))
            tune_idx.append(idx[:cut])
            val_idx.append(idx[cut:])
        tune_idx = np.concatenate(tune_idx)
        val_idx = np.concatenate(val_idx)

        print(f"\n[{tag}] tune rows={len(tune_idx)}  validation rows={len(val_idx)}")
        print(f"[{tag}] classes in tune={len(set(ytr[tune_idx]))}  in val={len(set(ytr[val_idx]))}")

        Xt, yt = Xtr_l[tune_idx], ytr[tune_idx]
        Xv, yv = Xtr_l[val_idx], ytr[val_idx]

        for name, spec in get_specs().items():
            t0 = time.time()
            # manual grid search scored on the validation block
            best = None
            keys = list(spec['grid'].keys())
            for combo in itertools.product(*[spec['grid'][k] for k in keys]):
                params = dict(zip(keys, combo))
                est = spec['est']
                from sklearn.base import clone
                m = clone(est).set_params(**params)
                m.fit(Xt, yt)
                vf1 = f1_score(yv, m.predict(Xv), average='macro', zero_division=0)
                if best is None or vf1 > best[0]:
                    best = (vf1, params, m)
            vf1, params, fitted = best

            # refit best params on the FULL train block, then score test
            from sklearn.base import clone
            full = clone(spec['est']).set_params(**params)
            full.fit(Xtr_l, ytr)
            pred = full.predict(Xte_l)
            r = metrics_row(name, yte, pred)
            r['Feature_Set'] = tag
            r['Validation_Macro_F1'] = round(float(vf1), 4)
            r['Best_Params'] = str(params)
            r['Tune_Time_Sec'] = round(time.time() - t0, 2)
            all_rows.append(r)
            print(f"  {name:<22} val_macroF1={vf1:.4f}  test_acc={r['Test_Accuracy']:.4f} "
                  f"test_macroF1={r['Macro_F1']:.4f}")

        sub = pd.DataFrame([r for r in all_rows if r['Feature_Set'] == tag])
        winner = sub.loc[sub['Validation_Macro_F1'].idxmax()]
        sel_rows.append({
            'Feature_Set': tag,
            'Selected_By_Validation': winner['Model'],
            'Validation_Macro_F1': winner['Validation_Macro_F1'],
            'Its_Test_Accuracy': winner['Test_Accuracy'],
            'Its_Test_Macro_F1': winner['Macro_F1'],
            'Best_Test_Accuracy_In_Set': round(float(sub['Test_Accuracy'].max()), 4),
            'Model_With_Best_Test_Accuracy': sub.loc[sub['Test_Accuracy'].idxmax(), 'Model'],
        })

    out = pd.DataFrame(all_rows)[['Feature_Set','Model','Validation_Macro_F1','Test_Accuracy',
        'Macro_Precision','Macro_Recall','Macro_F1','Weighted_F1','Best_Params','Tune_Time_Sec']]
    for tag in ['R1','R2']:
        out[out['Feature_Set']==tag].to_csv(
            os.path.join(OUT, f'validation_block_metrics_{tag}.csv'), index=False)

    sel = pd.DataFrame(sel_rows)
    sel.to_csv(os.path.join(OUT, 'validation_block_selection.csv'), index=False)

    print("\n" + "=" * 78)
    print("VALIDATION-BLOCK METRICS")
    print("=" * 78)
    print(out.to_string(index=False))
    print("\n" + "=" * 78)
    print("SELECTION (by validation macro F1 only)")
    print("=" * 78)
    print(sel.to_string(index=False))
    print(f"\nSaved: {OUT}/validation_block_metrics_R1.csv, _R2.csv, validation_block_selection.csv")
    return out, sel


if __name__ == '__main__':
    data = build_all()
    for tag in ['R1','R2']:
        print(f"{tag}: train={data[tag][0].shape} test={data[tag][2].shape}")
    task1(data)
    task2(data)
    print("\nDONE")
