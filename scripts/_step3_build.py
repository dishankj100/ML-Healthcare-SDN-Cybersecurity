"""
STEP 3 (part A): build R1 and R2 feature sets, report row retention.

R1 = single-row features, no history, no ip_duration.
R2 = per-flow deltas keyed on (src, dst, in_port), backward-looking only,
     computed on the whole file in original row order, then split.

Saves results/rate_features/r2_row_retention.csv
"""
import os
import numpy as np
import pandas as pd

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

R1_COLS = ['ip_bytes','ip_packet','ip_bytes_per_packet',
           'port_rx_bytes_rate','port_tx_bytes_rate','port_rx_packets_rate',
           'port_rx_bytes_per_packet','port_flow_count','table_active_count']

R2_COLS = ['rx_bytes_rate','tx_bytes_rate','rx_packets_rate',
           'delta_bytes_per_packet','port_flow_count','table_active_count']


def load_clean(fp):
    df = pd.read_csv(fp, names=ALL_COLUMNS, low_memory=False)
    for c in F9 + ['port_duration_sec','ip_duration']:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    df = df.dropna(subset=F9).reset_index(drop=True)
    return df


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
    """Backward-looking per-key deltas. Returns (feature_df, diag_dict, valid_mask)."""
    d = df.copy()
    d['_orig'] = np.arange(len(d))
    g = d.groupby(['src','dst','in_port'], sort=False)
    prx_b = g['port_rx_bytes'].shift(1)
    ptx_b = g['port_tx_bytes'].shift(1)
    prx_p = g['port_rx_packets'].shift(1)
    pt    = g['port_duration_sec'].shift(1)

    dt    = d['port_duration_sec'] - pt
    drx_b = d['port_rx_bytes'] - prx_b
    dtx_b = d['port_tx_bytes'] - ptx_b
    drx_p = d['port_rx_packets'] - prx_p

    first   = prx_b.isna()
    zero_t  = (~first) & (dt == 0)
    neg     = (~first) & (~zero_t) & ((drx_b < 0) | (dtx_b < 0) | (drx_p < 0))
    valid   = (~first) & (dt > 0) & (drx_b >= 0) & (dtx_b >= 0) & (drx_p >= 0)

    out = pd.DataFrame(index=df.index)
    out['rx_bytes_rate'] = np.where(valid, drx_b / dt.replace(0, np.nan), np.nan)
    out['tx_bytes_rate'] = np.where(valid, dtx_b / dt.replace(0, np.nan), np.nan)
    out['rx_packets_rate'] = np.where(valid, drx_p / dt.replace(0, np.nan), np.nan)
    out['delta_bytes_per_packet'] = np.where(valid & (drx_p > 0),
                                             drx_b / drx_p.replace(0, np.nan), 0.0)
    out['port_flow_count'] = df['port_flow_count'].astype(float)
    out['table_active_count'] = df['table_active_count'].astype(float)

    # time-change distribution over rows that HAVE a previous observation
    has_prev = (~first).values
    dt_prev = dt[has_prev].values
    diag = {
        'Rows_Total': int(len(df)),
        'Distinct_Keys': int(g.ngroups),
        'Dropped_First_Observation': int(first.sum()),
        'Dropped_Zero_Time_Change': int(zero_t.sum()),
        'Dropped_Negative_Delta': int(neg.sum()),
        'Rows_Retained': int(valid.sum()),
        'Retained_Pct': round(float(valid.mean() * 100), 2),
        'Time_Delta_Median': round(float(np.median(dt_prev)), 4) if len(dt_prev) else float('nan'),
        'Time_Delta_P90': round(float(np.percentile(dt_prev, 90)), 4) if len(dt_prev) else float('nan'),
        'Time_Delta_Zero_Pct': round(float((dt_prev == 0).mean() * 100), 2) if len(dt_prev) else float('nan'),
        'Zero_Denom_ip_packet': int((df['ip_packet'] == 0).sum()),
        'Zero_Denom_rx_packets': int((df['port_rx_packets'] == 0).sum()),
    }
    return out, diag, valid.values


def main():
    rows = []
    for cname, fp in TC:
        df = load_clean(fp)
        _, diag, valid = build_r2(df)
        diag['Class'] = cname
        rows.append(diag)
        print(f"[{cname:<13}] total={diag['Rows_Total']:<7} keys={diag['Distinct_Keys']:<5} "
              f"first_obs={diag['Dropped_First_Observation']:<5} dt==0={diag['Dropped_Zero_Time_Change']:<7} "
              f"neg={diag['Dropped_Negative_Delta']:<5} retained={diag['Rows_Retained']:<7} "
              f"({diag['Retained_Pct']:>5.2f}%)  dt med={diag['Time_Delta_Median']} p90={diag['Time_Delta_P90']} "
              f"zero%={diag['Time_Delta_Zero_Pct']}")

    out = pd.DataFrame(rows)[['Class','Rows_Total','Distinct_Keys','Dropped_First_Observation',
        'Dropped_Zero_Time_Change','Dropped_Negative_Delta','Rows_Retained','Retained_Pct',
        'Time_Delta_Median','Time_Delta_P90','Time_Delta_Zero_Pct',
        'Zero_Denom_ip_packet','Zero_Denom_rx_packets']]
    out.to_csv(os.path.join(OUT, 'r2_row_retention.csv'), index=False)

    print("\n" + "=" * 78)
    print(out.to_string(index=False))
    print("\nSaved: results/rate_features/r2_row_retention.csv")

    print("\n" + "=" * 78)
    print("30% ROW-LOSS GUARD")
    print("=" * 78)
    out['Loss_Pct'] = (100 - out['Retained_Pct']).round(2)
    breached = out[out['Loss_Pct'] > 30.0]
    for _, r in out.iterrows():
        flag = 'BREACH' if r['Loss_Pct'] > 30.0 else 'ok'
        print(f"  {r['Class']:<14} loss={r['Loss_Pct']:>6.2f}%  {flag}")
    print(f"\nClasses over 30% loss: {len(breached)}")
    if len(breached):
        print("STOP CONDITION MET - do not train.")
    else:
        print("All classes under 30% loss - safe to train.")


if __name__ == '__main__':
    main()
