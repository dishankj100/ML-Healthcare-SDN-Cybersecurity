"""
STEP 2: Inspect data structure before building rate features.

For each training file reports:
  - polling-cycle size: how many consecutive rows share the same port_duration_sec
  - whether in_port and src/dst identify a port/flow consistently across cycles
  - how often ip_duration is 0
  - min/max of ip_duration and port_duration_sec
Then decides whether per-port deltas between consecutive polling cycles are reliable.
"""
import numpy as np
import pandas as pd

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


def inspect(cname, fp):
    df = pd.read_csv(fp, names=ALL_COLUMNS, low_memory=False)
    for c in F + ['port_duration_sec','ip_duration']:
        df[c] = pd.to_numeric(df[c], errors='coerce')
    raw_n = len(df)
    df = df.dropna(subset=F).reset_index(drop=True)
    n = len(df)

    # --- polling cycle structure ---
    pdur = df['port_duration_sec'].values
    # run-length encode consecutive equal port_duration_sec
    change = np.flatnonzero(np.diff(pdur) != 0) + 1
    starts = np.concatenate(([0], change))
    ends = np.concatenate((change, [n]))
    run_lengths = ends - starts
    n_cycles = len(run_lengths)

    # --- does in_port identify a port consistently across cycles? ---
    # within each cycle, how many distinct in_port values?
    ports_per_cycle = pd.Series(df['in_port'].values).groupby(
        np.repeat(np.arange(n_cycles), run_lengths)).nunique()
    # how many distinct in_port overall
    n_ports = df['in_port'].nunique()
    # if in_port identifies a port, each cycle should have exactly n_ports rows
    modal_len = pd.Series(run_lengths).mode()
    modal_len = int(modal_len.iloc[0]) if len(modal_len) else -1
    cycles_matching_modal = int((run_lengths == modal_len).sum())

    # --- do src/dst identify a flow consistently? ---
    flow_key = df['src'].astype(str) + '|' + df['dst'].astype(str)
    n_flows = flow_key.nunique()
    flows_per_cycle = flow_key.groupby(np.repeat(np.arange(n_cycles), run_lengths)).nunique()

    # --- ip_duration zeros ---
    ipd = df['ip_duration'].values
    ip_zero = int((ipd == 0).sum())
    ip_zero_pct = ip_zero / n * 100

    # --- ranges ---
    return {
        'Class': cname,
        'File': fp.split('/')[-1],
        'Rows_Raw': raw_n,
        'Rows_Clean': n,
        'Distinct_port_duration_sec': int(pd.Series(pdur).nunique()),
        'Polling_Cycles': n_cycles,
        'Modal_Cycle_Size': modal_len,
        'Cycles_At_Modal_Size': cycles_matching_modal,
        'Cycles_At_Modal_Pct': round(cycles_matching_modal / n_cycles * 100, 2),
        'Cycle_Size_Min': int(run_lengths.min()),
        'Cycle_Size_Max': int(run_lengths.max()),
        'Distinct_in_port': n_ports,
        'Distinct_src_dst_flows': n_flows,
        'Ports_Per_Cycle_Min': int(ports_per_cycle.min()),
        'Ports_Per_Cycle_Max': int(ports_per_cycle.max()),
        'Flows_Per_Cycle_Min': int(flows_per_cycle.min()),
        'Flows_Per_Cycle_Max': int(flows_per_cycle.max()),
        'ip_duration_Zero_Count': ip_zero,
        'ip_duration_Zero_Pct': round(ip_zero_pct, 2),
        'ip_duration_Min': float(np.nanmin(ipd)),
        'ip_duration_Max': float(np.nanmax(ipd)),
        'port_duration_sec_Min': float(np.nanmin(pdur)),
        'port_duration_sec_Max': float(np.nanmax(pdur)),
    }


def main():
    rows = []
    for cname, fp in TC:
        r = inspect(cname, fp)
        rows.append(r)
        print(f"[{cname:<13}] rows={r['Rows_Clean']:<7} cycles={r['Polling_Cycles']:<6} "
              f"modal_size={r['Modal_Cycle_Size']:<4} ({r['Cycles_At_Modal_Pct']:>5.1f}% of cycles) "
              f"in_port={r['Distinct_in_port']:<3} flows={r['Distinct_src_dst_flows']:<6} "
              f"ip_dur==0: {r['ip_duration_Zero_Pct']:>5.1f}%")

    out = pd.DataFrame(rows)
    out.to_csv('results/data_structure_inspection.csv', index=False)
    print("\n" + "=" * 78)
    print(out.to_string(index=False))
    print("\nSaved: results/data_structure_inspection.csv")

    # --- Can per-port deltas be computed reliably? ---
    print("\n" + "=" * 78)
    print("DELTA FEASIBILITY CHECK")
    print("=" * 78)
    for cname, fp in TC:
        df = pd.read_csv(fp, names=ALL_COLUMNS, low_memory=False)
        for c in F + ['port_duration_sec','ip_duration']:
            df[c] = pd.to_numeric(df[c], errors='coerce')
        df = df.dropna(subset=F).reset_index(drop=True)
        pdur = df['port_duration_sec'].values
        change = np.flatnonzero(np.diff(pdur) != 0) + 1
        starts = np.concatenate(([0], change))
        ends = np.concatenate((change, [len(df)]))
        run_lengths = ends - starts

        # Are cycles rectangular (same set of in_port each cycle)?
        cyc_id = np.repeat(np.arange(len(run_lengths)), run_lengths)
        grp = df.groupby(cyc_id)
        ports_per_cycle = grp['in_port'].nunique()
        rectangular = bool((ports_per_cycle == ports_per_cycle.iloc[0]).all())

        # Duplicate in_port within a cycle would break a port-keyed delta
        dup_within = int(grp['in_port'].apply(lambda s: s.duplicated().sum()).sum())

        # Monotonicity of the cumulative counters within a port across cycles
        monotonic_ok = True
        if rectangular:
            piv = df.assign(cyc=cyc_id).pivot_table(
                index='cyc', columns='in_port', values='port_rx_bytes', aggfunc='first')
            diffs = piv.diff().iloc[1:]
            neg = int((diffs < 0).sum().sum())
            total = int(diffs.notna().sum().sum())
            monotonic_ok = (neg == 0)

        print(f"  {cname:<13} rectangular={str(rectangular):<5} dup_in_port_within_cycle={dup_within:<6} "
              f"rx_bytes_non_decreasing={monotonic_ok}")


if __name__ == '__main__':
    main()
