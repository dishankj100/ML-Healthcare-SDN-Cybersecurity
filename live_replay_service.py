"""
HealthGuard AI: Live Replay Service
===================================
Backend engine supporting the Live Lab Replay Simulation:
- Streams real test-partition rows from MCAD-SDN dataset captures
- Strictly isolates temporal test rows (rows after 70% train split + 200-row gap)
- Supports UNSEEN SOURCE scenarios (normal_iperf.csv, normal_internet1.csv) streaming all rows
- Evaluates using live_model.joblib (Random Forest on R1 temporal train set)
- Computes global model feature importances
- Dynamically parses honest limits from per_class_metrics.csv, confusion_matrix.csv, and audit CSVs
- Strict manual input validation (negative numbers, duration <= 0, inconsistent packet counts, non-numeric)
"""

import os
import random
import numpy as np
import pandas as pd
import joblib

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

SCENARIOS = [
    ('Normal', 'Archieve/normal_ditg.csv'),
    ('BruteForce', 'Archieve/attack_bruteforce.csv'),
    ('CMD', 'Archieve/attack_cmd.csv'),
    ('TCPDDOS', 'Archieve/attack_ddos_tcp.csv'),
    ('UDPDDOS', 'Archieve/attack_ddos_udp.csv'),
    ('Probe', 'Archieve/attack_os_port_scan.csv'),
    ('Smaba', 'Archieve/attack_samba.csv'),
    ('SQLInjection', 'Archieve/attack_sql_injection.csv'),
    ('VNC', 'Archieve/attack_vnc.csv')
]

UNSEEN_SCENARIOS = [
    ('UNSEEN: normal_iperf', 'Archieve/normal_iperf.csv'),
    ('UNSEEN: normal_internet1', 'Archieve/normal_internet1.csv')
]

CLASS_NAMES = sorted([c[0] for c in SCENARIOS])
CLASS_TO_ID = {n: i for i, n in enumerate(CLASS_NAMES)}
ID_TO_CLASS = {i: n for i, n in enumerate(CLASS_NAMES)}

CLASS_METADATA = {
    'Normal': {'severity': 'SAFE', 'color': '#10b981', 'target': 'Philips IntelliVue MX800 ICU Monitor', 'ip': '10.0.1.15'},
    'BruteForce': {'severity': 'HIGH', 'color': '#f59e0b', 'target': 'Cardiology Nurse Terminal', 'ip': '10.0.4.50'},
    'CMD': {'severity': 'CRITICAL', 'color': '#ef4444', 'target': 'Pathology Analyzer Server', 'ip': '10.0.3.12'},
    'TCPDDOS': {'severity': 'CRITICAL', 'color': '#ef4444', 'target': 'Core OpenFlow SDN Switch', 'ip': '10.0.0.2'},
    'UDPDDOS': {'severity': 'HIGH', 'color': '#f59e0b', 'target': 'Telehealth Surgical Bridge', 'ip': '10.0.4.80'},
    'Probe': {'severity': 'MEDIUM', 'color': '#06b6d4', 'target': 'Alaris Infusion Pump Cluster', 'ip': '10.0.1.22'},
    'Smaba': {'severity': 'HIGH', 'color': '#f59e0b', 'target': 'PACS Radiology Storage Server', 'ip': '10.0.2.14'},
    'SQLInjection': {'severity': 'CRITICAL', 'color': '#ef4444', 'target': 'Epic Systems EHR Database', 'ip': '10.0.2.10'},
    'VNC': {'severity': 'HIGH', 'color': '#f59e0b', 'target': 'Operating Room Surgical Display', 'ip': '10.0.4.85'}
}


class LiveReplayService:
    def __init__(self, model_path='live_model.joblib'):
        self.model_path = model_path
        self.bundle = None
        self.model = None
        self.scaler = None
        self.test_cache = {}
        self.unseen_cache = {}
        self.scenario_metadata = {}
        self.load_model()
        self.load_test_partitions()
        self.load_unseen_sources()

    def load_model(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Live model bundle {self.model_path} not found. Run scripts/train_live_model.py first.")
        self.bundle = joblib.load(self.model_path)
        self.model = self.bundle['model']
        self.scaler = self.bundle['scaler']

    def load_test_partitions(self):
        """
        Loads and caches ONLY the temporal test partition (last ~30% after 200-row gap)
        for each benchmark scenario. Train rows and gap rows are never stored in test_cache.
        """
        for cname, fpath in SCENARIOS:
            if not os.path.exists(fpath):
                continue
            df = pd.read_csv(fpath, names=ALL_COLUMNS, low_memory=False)
            for c in F9 + ['port_duration_sec', 'ip_duration']:
                df[c] = pd.to_numeric(df[c], errors='coerce')
            df = df.dropna(subset=F9 + ['port_duration_sec']).reset_index(drop=True)
            n = len(df)
            train_end = int(np.floor(n * 0.70))
            test_start = train_end + 200

            # Tag original dataset row index before slicing
            df['dataset_row_index'] = df.index

            # Strict test slice: ONLY rows from test_start to n
            test_slice = df.iloc[test_start:].copy().reset_index(drop=True)
            self.test_cache[cname] = test_slice
            self.scenario_metadata[cname] = {
                'total_clean_rows': n,
                'train_rows': train_end,
                'gap_rows': 200,
                'test_start_index': test_start,
                'test_rows': len(test_slice),
                'is_unseen': False
            }

    def load_unseen_sources(self):
        """
        Loads UNSEEN source traffic files (normal_iperf.csv, normal_internet1.csv).
        None of these rows were in training, so all rows are available for streaming.
        """
        for uname, fpath in UNSEEN_SCENARIOS:
            if not os.path.exists(fpath):
                continue
            df = pd.read_csv(fpath, names=ALL_COLUMNS, low_memory=False)
            for c in F9 + ['port_duration_sec', 'ip_duration']:
                df[c] = pd.to_numeric(df[c], errors='coerce')
            df = df.dropna(subset=F9 + ['port_duration_sec']).reset_index(drop=True)
            df['dataset_row_index'] = df.index
            self.unseen_cache[uname] = df
            self.scenario_metadata[uname] = {
                'total_clean_rows': len(df),
                'train_rows': 0,
                'gap_rows': 0,
                'test_start_index': 0,
                'test_rows': len(df),
                'is_unseen': True
            }

    def derive_r1_features(self, raw_dict):
        """Derives R1 rate features from raw counter values with zero-division protection."""
        ip_bytes = float(raw_dict['ip_bytes'])
        ip_packet = float(raw_dict['ip_packet'])
        port_rx_bytes = float(raw_dict['port_rx_bytes'])
        port_tx_bytes = float(raw_dict['port_tx_bytes'])
        port_rx_packets = float(raw_dict['port_rx_packets'])
        port_duration_sec = float(raw_dict['port_duration_sec'])
        port_flow_count = float(raw_dict['port_flow_count'])
        table_active_count = float(raw_dict['table_active_count'])

        if port_duration_sec <= 0:
            raise ValueError("port_duration_sec must be strictly positive (> 0) to compute uptime rates.")

        ip_bytes_per_packet = ip_bytes / ip_packet if ip_packet > 0 else 0.0
        port_rx_bytes_rate = port_rx_bytes / port_duration_sec
        port_tx_bytes_rate = port_tx_bytes / port_duration_sec
        port_rx_packets_rate = port_rx_packets / port_duration_sec
        port_rx_bytes_per_packet = port_rx_bytes / port_rx_packets if port_rx_packets > 0 else 0.0

        r1_vector = [
            ip_bytes,
            ip_packet,
            ip_bytes_per_packet,
            port_rx_bytes_rate,
            port_tx_bytes_rate,
            port_rx_packets_rate,
            port_rx_bytes_per_packet,
            port_flow_count,
            table_active_count
        ]
        return r1_vector, {
            'ip_bytes_per_packet': round(ip_bytes_per_packet, 4),
            'port_rx_bytes_rate': round(port_rx_bytes_rate, 4),
            'port_tx_bytes_rate': round(port_tx_bytes_rate, 4),
            'port_rx_packets_rate': round(port_rx_packets_rate, 4),
            'port_rx_bytes_per_packet': round(port_rx_bytes_per_packet, 4)
        }

    def _transform_r1(self, r1_vector):
        """Applies log1p to rate features and scales with train-fit StandardScaler."""
        arr = np.array([r1_vector], dtype=float)
        log_indices = [R1_COLS.index(c) for c in R1_LOG]
        arr[:, log_indices] = np.log1p(np.clip(arr[:, log_indices], 0, None))
        scaled = self.scaler.transform(arr)
        return scaled

    def get_global_feature_importances(self):
        """
        Returns global Gini feature importances directly from live_model.
        Clearly labeled as global model importances, not per-prediction SHAP values.
        """
        importances = getattr(self.model, 'feature_importances_', [1.0 / len(R1_COLS)] * len(R1_COLS))
        results = []
        for name, imp in zip(R1_COLS, importances):
            results.append({
                'feature': name,
                'importance': round(float(imp), 4),
                'importance_pct': round(float(imp) * 100, 2)
            })
        results.sort(key=lambda x: x['importance'], reverse=True)
        return {
            'panel_title': 'Feature importance (global)',
            'attribution_type': 'Global Gini Importance (Random Forest 100 trees, temporal train set)',
            'disclaimer': 'These reflect overall model reliance learned during training across all classes, not local per-prediction SHAP attributions.',
            'features': results
        }

    def stream_next(self, scenario='Mixed random', row_idx=None):
        """
        Fetches the next row for auto-fetch streaming mode.
        - For benchmark scenarios: draws strictly from temporal test portion (after 70% + 200 gap).
        - For 'Mixed random': samples strictly from the 9 benchmark test portions.
        - For UNSEEN scenarios: streams from all rows (none were in training), true_label = 'Normal (unseen source)'.
        """
        is_unseen = scenario in self.unseen_cache
        if is_unseen:
            df_stream = self.unseen_cache[scenario]
            selected_scenario = scenario
            true_label = "Normal (unseen source)"
        elif scenario == 'Mixed random' or scenario not in self.test_cache:
            selected_scenario = random.choice(list(self.test_cache.keys()))
            df_stream = self.test_cache[selected_scenario]
            true_label = selected_scenario
        else:
            selected_scenario = scenario
            df_stream = self.test_cache[selected_scenario]
            true_label = selected_scenario

        meta = self.scenario_metadata[selected_scenario]
        total_rows = len(df_stream)

        if row_idx is None or row_idx >= total_rows:
            target_idx = random.randint(0, total_rows - 1) if scenario == 'Mixed random' else (0 if row_idx is not None else 0)
        else:
            target_idx = row_idx % total_rows

        row = df_stream.iloc[target_idx]
        dataset_row_idx = int(row['dataset_row_index'])

        raw_dict = {
            'src': str(row.get('src', '10.0.0.1')),
            'dst': str(row.get('dst', '10.0.0.2')),
            'ip_bytes': float(row['ip_bytes']),
            'ip_packet': float(row['ip_packet']),
            'port_rx_bytes': float(row['port_rx_bytes']),
            'port_tx_bytes': float(row['port_tx_bytes']),
            'port_rx_packets': float(row['port_rx_packets']),
            'port_duration_sec': float(row['port_duration_sec']),
            'port_flow_count': float(row['port_flow_count']),
            'table_active_count': float(row['table_active_count']),
        }

        r1_vec, derived_dict = self.derive_r1_features(raw_dict)
        scaled_arr = self._transform_r1(r1_vec)

        pred_class_id = int(self.model.predict(scaled_arr)[0])
        pred_label = ID_TO_CLASS[pred_class_id]
        probs = self.model.predict_proba(scaled_arr)[0]
        confidence = float(probs[pred_class_id])

        pred_meta = CLASS_METADATA.get(pred_label, CLASS_METADATA['Normal'])

        # Determine correctness: for unseen sources, true label is Normal
        if is_unseen:
            is_correct = (pred_label == 'Normal')
        else:
            is_correct = (pred_label == selected_scenario)

        return {
            'scenario': selected_scenario,
            'true_label': true_label,
            'is_unseen_source': is_unseen,
            'test_row_index': target_idx,
            'dataset_row_index': dataset_row_idx,
            'test_start_index': meta['test_start_index'],
            'total_scenario_test_rows': total_rows,
            'next_index': (target_idx + 1) % total_rows,
            'raw_parameters': raw_dict,
            'derived_features': derived_dict,
            'prediction': {
                'class_id': pred_class_id,
                'class_name': pred_label,
                'is_attack': pred_label != 'Normal',
                'is_correct': is_correct,
                'confidence': round(confidence, 4),
                'confidence_pct': round(confidence * 100, 2),
                'severity': pred_meta['severity'],
                'color': pred_meta['color'],
                'target_asset': pred_meta['target'],
                'probabilities': {ID_TO_CLASS[i]: round(float(p), 4) for i, p in enumerate(probs)}
            }
        }

    def predict_manual(self, form_data):
        """
        Evaluates manual entry form inputs with strict cybersecurity validation rules:
        - Rejects non-numeric input with a clear error message
        - Rejects negative values for any telemetry parameter
        - Rejects port_duration_sec <= 0 (cannot compute rate or invalid uptime)
        - Rejects inconsistent packet counts (packet == 0 with bytes > 0)
        """
        required = [
            'ip_bytes', 'ip_packet', 'port_rx_bytes', 'port_tx_bytes',
            'port_rx_packets', 'port_duration_sec', 'port_flow_count', 'table_active_count'
        ]

        cleaned = {}
        for k in required:
            if k not in form_data:
                raise ValueError(f"Missing required telemetry parameter: '{k}'.")
            val_raw = form_data[k]
            try:
                val = float(val_raw)
            except (ValueError, TypeError):
                raise ValueError(f"Invalid non-numeric input for '{k}': expected numeric value, got '{val_raw}'.")

            if val < 0:
                raise ValueError(f"Invalid parameter '{k}': counters cannot be negative ({val}).")
            if k == 'port_duration_sec' and val <= 0:
                raise ValueError(f"Invalid parameter 'port_duration_sec': switch connection duration must be strictly positive (> 0), got {val}.")
            cleaned[k] = val

        # Inconsistent packet telemetry validation
        if cleaned['ip_packet'] == 0 and cleaned['ip_bytes'] > 0:
            raise ValueError(f"Inconsistent packet telemetry: 'ip_packet' cannot be 0 when 'ip_bytes' is non-zero ({cleaned['ip_bytes']}).")

        if cleaned['port_rx_packets'] == 0 and cleaned['port_rx_bytes'] > 0:
            raise ValueError(f"Inconsistent packet telemetry: 'port_rx_packets' cannot be 0 when 'port_rx_bytes' is non-zero ({cleaned['port_rx_bytes']}).")

        r1_vec, derived_dict = self.derive_r1_features(cleaned)
        scaled_arr = self._transform_r1(r1_vec)

        pred_class_id = int(self.model.predict(scaled_arr)[0])
        pred_label = ID_TO_CLASS[pred_class_id]
        probs = self.model.predict_proba(scaled_arr)[0]
        confidence = float(probs[pred_class_id])

        pred_meta = CLASS_METADATA.get(pred_label, CLASS_METADATA['Normal'])

        return {
            'status': 'success',
            'raw_parameters': cleaned,
            'derived_features': derived_dict,
            'prediction': {
                'class_id': pred_class_id,
                'class_name': pred_label,
                'is_attack': pred_label != 'Normal',
                'confidence': round(confidence, 4),
                'confidence_pct': round(confidence * 100, 2),
                'severity': pred_meta['severity'],
                'color': pred_meta['color'],
                'target_asset': pred_meta['target'],
                'probabilities': {ID_TO_CLASS[i]: round(float(p), 4) for i, p in enumerate(probs)}
            }
        }

    def get_sample_row(self, scenario='Normal', offset=0):
        """
        Returns genuine test-set parameters for populating the manual example loader.
        Strictly draws from the temporal test portion (dataset_row_index >= test_start_index).
        """
        if scenario in self.unseen_cache:
            df_sample = self.unseen_cache[scenario]
            meta = self.scenario_metadata[scenario]
        else:
            if scenario not in self.test_cache:
                scenario = 'Normal'
            df_sample = self.test_cache[scenario]
            meta = self.scenario_metadata[scenario]

        idx = offset % len(df_sample)
        sample = df_sample.iloc[idx]
        return {
            'scenario': scenario,
            'test_row_index': idx,
            'dataset_row_index': int(sample['dataset_row_index']),
            'test_start_index': meta['test_start_index'],
            'ip_bytes': float(sample['ip_bytes']),
            'ip_packet': float(sample['ip_packet']),
            'port_rx_bytes': float(sample['port_rx_bytes']),
            'port_tx_bytes': float(sample['port_tx_bytes']),
            'port_rx_packets': float(sample['port_rx_packets']),
            'port_duration_sec': float(sample['port_duration_sec']),
            'port_flow_count': float(sample['port_flow_count']),
            'table_active_count': float(sample['table_active_count'])
        }

    def get_honest_limits(self):
        """
        Loads and returns dynamic, unhardcoded evaluation limits from results/*.csv.
        Reads per_class_metrics.csv and confusion_matrix.csv to surface weakest classes
        and exact misclassifications without hardcoding.
        """
        limits = {
            'dataset_source': 'MCAD-SDN Healthcare Benchmark Dataset',
            'temporal_split_accuracy': 0.0,
            'temporal_macro_f1': 0.0,
            'weakest_recall_class': 'None',
            'weakest_recall_val': 0.0,
            'weakest_recall_confusions': [],
            'weakest_precision_class': 'None',
            'weakest_precision_val': 0.0,
            'weakest_precision_confusions': [],
            'iperf_normal_accuracy_pct': 0.0,
            'iperf_false_positive_pct': 0.0,
            'iperf_top_false_label': 'BruteForce',
            'key_caveat': 'On out-of-distribution traffic (e.g. normal_iperf.csv), high packet/volume rates mimic BruteForce signatures, producing substantial false positives.',
            'hypothesis': 'Flow-level and port-level counters may not carry sufficient application-layer payload signal to distinguish certain web/database attack vectors (e.g. SQL Injection vs Command Injection), as an untested hypothesis.'
        }

        # 1. Read overall metrics
        metrics_p = 'results/live_replay/model_metrics.csv'
        if os.path.exists(metrics_p):
            try:
                m_df = pd.read_csv(metrics_p)
                limits['temporal_split_accuracy'] = float(m_df['Test_Accuracy'].iloc[0])
                limits['temporal_macro_f1'] = float(m_df['Macro_F1'].iloc[0])
            except Exception:
                pass

        # 2. Read per-class report to find lowest recall and precision
        per_class_p = 'results/live_replay/per_class_metrics.csv'
        if os.path.exists(per_class_p):
            try:
                pc_df = pd.read_csv(per_class_p)
                min_rec_row = pc_df.loc[pc_df['Recall'].idxmin()]
                min_prec_row = pc_df.loc[pc_df['Precision'].idxmin()]
                limits['weakest_recall_class'] = str(min_rec_row['Class'])
                limits['weakest_recall_val'] = float(min_rec_row['Recall'])
                limits['weakest_precision_class'] = str(min_prec_row['Class'])
                limits['weakest_precision_val'] = float(min_prec_row['Precision'])
            except Exception:
                pass

        # 3. Read confusion matrix to determine exact confusions for weakest classes
        cm_p = 'results/live_replay/confusion_matrix.csv'
        if os.path.exists(cm_p):
            try:
                cm_df = pd.read_csv(cm_p, index_col=0)
                # Parse confusions for weakest recall class
                rec_target = limits['weakest_recall_class']
                row_key = f"True_{rec_target}"
                if row_key in cm_df.index:
                    row_data = cm_df.loc[row_key]
                    total_row = float(row_data.sum())
                    rec_confusions = []
                    for col_key, cnt in row_data.items():
                        c_pred = col_key.replace("Pred_", "")
                        if c_pred != rec_target and cnt > 0:
                            rec_confusions.append({
                                'predicted_as': c_pred,
                                'count': int(cnt),
                                'pct': round((float(cnt) / total_row) * 100, 2)
                            })
                    rec_confusions.sort(key=lambda x: x['count'], reverse=True)
                    limits['weakest_recall_confusions'] = rec_confusions

                # Parse false positive sources for weakest precision class
                prec_target = limits['weakest_precision_class']
                col_key = f"Pred_{prec_target}"
                if col_key in cm_df.columns:
                    col_data = cm_df[col_key]
                    total_col = float(col_data.sum())
                    prec_confusions = []
                    for r_key, cnt in col_data.items():
                        c_true = r_key.replace("True_", "")
                        if c_true != prec_target and cnt > 0:
                            prec_confusions.append({
                                'true_class': c_true,
                                'count': int(cnt),
                                'pct': round((float(cnt) / total_col) * 100, 2)
                            })
                    prec_confusions.sort(key=lambda x: x['count'], reverse=True)
                    limits['weakest_precision_confusions'] = prec_confusions
            except Exception:
                pass

        # 4. Out-of-distribution audit
        audit_p = 'results/rate_features/r1_lr_audit.csv'
        if os.path.exists(audit_p):
            try:
                a_df = pd.read_csv(audit_p)
                iperf_row = a_df[(a_df.get('File') == 'normal_iperf.csv')]
                if len(iperf_row) > 0:
                    pct_norm = float(iperf_row['Percent_Normal'].iloc[0])
                    limits['iperf_normal_accuracy_pct'] = pct_norm
                    limits['iperf_false_positive_pct'] = round(100.0 - pct_norm, 2)
            except Exception:
                pass

        return limits


# Global singleton service
live_service = None

def get_live_service():
    global live_service
    if live_service is None:
        live_service = LiveReplayService()
    return live_service
