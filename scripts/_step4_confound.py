"""
STEP 4: Confound baselines on the temporal split.

(i)   majority-class baseline
(ii)  Logistic Regression and Random Forest using ONLY port_duration_sec
(iii) same using ONLY table_active_count

Reported next to chance level and the cumulative-counter (F9) models.
Saves results/rate_features/confound_baselines.csv
"""
import os
import numpy as np
import pandas as pd

from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score

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


def build_temporal():
    """Same 70% / 200-row gap / 30% split as every prior experiment."""
    tr, te = [], []
    for cname, fp in TC:
        df = load_clean(fp)
        n = len(df)
        train_end = int(np.floor(n * 0.70))
        test_start = train_end + 200
        a = df.iloc[:train_end].copy()
        a['rel_time'] = np.linspace(0, 1, len(a))
        a['_label'] = CLASS_TO_ID[cname]
        b = df.iloc[test_start:].copy()
        b['_label'] = CLASS_TO_ID[cname]
        tr.append(a); te.append(b)
    train_df = pd.concat(tr, ignore_index=True).sort_values('rel_time').reset_index(drop=True)
    test_df = pd.concat(te, ignore_index=True)
    return train_df, test_df


def score(name, y_true, y_pred, note):
    return {
        'Baseline': name,
        'Test_Accuracy': round(float(accuracy_score(y_true, y_pred)), 4),
        'Macro_F1': round(float(f1_score(y_true, y_pred, average='macro', zero_division=0)), 4),
        'Weighted_F1': round(float(f1_score(y_true, y_pred, average='weighted', zero_division=0)), 4),
        'Features_Used': note,
    }


def main():
    print("=" * 78)
    print("STEP 4: Confound baselines (temporal split)")
    print("=" * 78)

    train_df, test_df = build_temporal()
    y_train = train_df['_label'].values
    y_test = test_df['_label'].values
    print(f"train rows={len(train_df)}  test rows={len(test_df)}")

    counts = pd.Series(y_test).value_counts().sort_index()
    print("\nTest-set class distribution:")
    for k, v in counts.items():
        print(f"  {ID_TO_CLASS[k]:<14} {v:>7}  ({v/len(y_test)*100:6.2f}%)")

    rows = []

    # ---- chance level ----
    n_classes = len(CLASS_NAMES)
    rows.append({
        'Baseline': 'Chance (uniform, 1/9)',
        'Test_Accuracy': round(1.0 / n_classes, 4),
        'Macro_F1': round(1.0 / n_classes, 4),
        'Weighted_F1': round(1.0 / n_classes, 4),
        'Features_Used': 'none (theoretical)',
    })

    # ---- majority class ----
    maj = counts.idxmax()
    maj_pred = np.full(len(y_test), maj)
    r = score('Majority class', y_test, maj_pred, 'none (constant prediction)')
    r['Baseline'] = f'Majority class ({ID_TO_CLASS[maj]})'
    rows.append(r)
    print(f"\nMajority class = {ID_TO_CLASS[maj]} ({counts.max()}/{len(y_test)} = "
          f"{counts.max()/len(y_test)*100:.2f}%)")

    # ---- single-feature models ----
    for feat in ['port_duration_sec', 'table_active_count']:
        Xtr = train_df[[feat]].values.astype(float)
        Xte = test_df[[feat]].values.astype(float)

        lr = Pipeline([('scaler', StandardScaler()),
                       ('clf', LogisticRegression(C=1.0, max_iter=1000, random_state=RANDOM_STATE))])
        lr.fit(Xtr, y_train)
        rows.append(score(f'Logistic Regression (scaled) on {feat} only',
                          y_test, lr.predict(Xte), feat))
        print(f"  LogReg on {feat:<20} done")

        rf = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1)
        rf.fit(Xtr, y_train)
        rows.append(score(f'Random Forest on {feat} only',
                          y_test, rf.predict(Xte), feat))
        print(f"  RF     on {feat:<20} done")

    # ---- reference: cumulative-counter models on the same test set ----
    orig = pd.read_csv('results/metrics.csv')
    for _, m in orig.iterrows():
        if m['Model'] in ['Logistic Regression', 'Random Forest']:
            rows.append({
                'Baseline': f"{m['Model']} on 9 cumulative counters (reference)",
                'Test_Accuracy': float(m['Test_Accuracy']),
                'Macro_F1': float(m['Macro_F1']),
                'Weighted_F1': float(m['Weighted_F1']),
                'Features_Used': '9 fixed features',
            })

    out = pd.DataFrame(rows)
    out.to_csv(os.path.join(OUT, 'confound_baselines.csv'), index=False)

    print("\n" + "=" * 78)
    print(out.to_string(index=False))
    print(f"\nSaved: {OUT}/confound_baselines.csv")


if __name__ == '__main__':
    main()
