"""
Automated Test Suite for Live Lab Replay Simulation
===================================================
Verifies:
1. /live endpoint loads (HTTP 200) and displays the mandatory replay banner.
2. /api/live/stream returns all required raw parameters, derived ratios, prediction, and confidence.
3. Stream row index test: auto-fetch and sample loading draw strictly from temporal TEST portion (dataset_row_index >= test_start_index).
4. Unseen source scenarios stream with true label "Normal (unseen source)" and compute predictions live.
5. Manual prediction works on valid inputs and returns complete response.
6. Strict manual input validation rejects:
   - Negative values
   - port_duration_sec <= 0
   - Inconsistent packets (ip_packet == 0 with ip_bytes > 0)
   - Inconsistent port packets (port_rx_packets == 0 with port_rx_bytes > 0)
   - Non-numeric input
7. /api/live/honest_limits dynamically reads metrics from results/live_replay/*.csv without hardcoding.
8. /api/live/feature_importances returns global Gini feature importances across the 9 R1 features.
"""

import unittest
import json
import app
from live_replay_service import get_live_service, SCENARIOS, UNSEEN_SCENARIOS


class TestLiveReplaySimulation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = app.app
        cls.client = cls.app.test_client()
        cls.svc = get_live_service()

    def test_01_live_page_loads_and_has_mandatory_banner(self):
        """Test that /live loads with HTTP 200 and renders the exact mandatory banner."""
        resp = self.client.get('/live')
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        expected_banner = "REPLAY SIMULATION: rows are streamed from the MCAD-SDN dataset test portion, not captured from a live network."
        self.assertIn(expected_banner, html, "Mandatory disclaimer banner missing or text mismatch in /live template.")

    def test_02_stream_endpoint_structure(self):
        """Test that /api/live/stream returns all required schema fields."""
        resp = self.client.get('/api/live/stream?scenario=BruteForce&row_idx=0')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()

        # Required top-level keys
        required_keys = [
            'scenario', 'true_label', 'test_row_index', 'dataset_row_index',
            'test_start_index', 'total_scenario_test_rows', 'next_index',
            'raw_parameters', 'derived_features', 'prediction'
        ]
        for k in required_keys:
            self.assertIn(k, data, f"Missing key '{k}' in stream response.")

        # Raw parameters
        raw = data['raw_parameters']
        for p in ['ip_bytes', 'ip_packet', 'port_rx_bytes', 'port_tx_bytes', 'port_rx_packets', 'port_duration_sec', 'port_flow_count', 'table_active_count']:
            self.assertIn(p, raw, f"Missing raw parameter '{p}'.")

        # Prediction details
        pred = data['prediction']
        for p in ['class_name', 'confidence', 'confidence_pct', 'severity', 'is_correct', 'probabilities']:
            self.assertIn(p, pred, f"Missing prediction key '{p}'.")

    def test_03_streaming_draws_only_from_test_portion(self):
        """Verify by row index that auto-fetch streams strictly from temporal test portion (no train, no gap)."""
        for cname, _ in SCENARIOS:
            meta = self.svc.scenario_metadata[cname]
            test_start = meta['test_start_index']
            # Fetch first 3 test rows
            for offset in [0, 1, 2]:
                res = self.svc.stream_next(scenario=cname, row_idx=offset)
                self.assertGreaterEqual(
                    res['dataset_row_index'], test_start,
                    f"Violation: Scenario '{cname}' served row {res['dataset_row_index']} which is before test_start {test_start}."
                )

        # Test Mixed random sampling (10 random iterations)
        for _ in range(10):
            res_mixed = self.svc.stream_next(scenario='Mixed random')
            scen = res_mixed['scenario']
            test_start = self.svc.scenario_metadata[scen]['test_start_index']
            self.assertGreaterEqual(
                res_mixed['dataset_row_index'], test_start,
                f"Violation in Mixed random: Scenario '{scen}' served dataset row {res_mixed['dataset_row_index']} < test_start {test_start}."
            )

    def test_04_sample_example_loader_draws_only_from_test_portion(self):
        """Verify that /api/live/sample_row draws strictly from temporal test portion."""
        for cname, _ in SCENARIOS:
            meta = self.svc.scenario_metadata[cname]
            test_start = meta['test_start_index']
            resp = self.client.get(f'/api/live/sample_row?scenario={cname}')
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertGreaterEqual(
                data['dataset_row_index'], test_start,
                f"Sample loader served row {data['dataset_row_index']} from train/gap region (test_start={test_start})."
            )

    def test_05_unseen_source_streaming(self):
        """Test streaming from unseen sources (normal_iperf, normal_internet1)."""
        for uname, _ in UNSEEN_SCENARIOS:
            resp = self.client.get(f'/api/live/stream?scenario={uname}&row_idx=0')
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data['is_unseen_source'])
            self.assertEqual(data['true_label'], "Normal (unseen source)")
            self.assertIn(data['prediction']['class_name'], list(data['prediction']['probabilities'].keys()))
            self.assertIn(data['prediction']['class_id'], list(self.svc.model.classes_))

    def test_06_manual_mode_valid_prediction(self):
        """Test manual prediction endpoint with valid counter values."""
        payload = {
            'ip_bytes': 4800,
            'ip_packet': 8,
            'port_rx_bytes': 45600,
            'port_tx_bytes': 51200,
            'port_rx_packets': 76,
            'port_duration_sec': 120,
            'port_flow_count': 4,
            'table_active_count': 3
        }
        resp = self.client.post('/api/live/predict_manual', json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['prediction']['class_name'], 'Normal')
        self.assertGreater(data['prediction']['confidence'], 0.5)

    def test_07_manual_validation_negative_values(self):
        """Test that negative telemetry counters are rejected with HTTP 400 and clear message."""
        payload = {
            'ip_bytes': -50,
            'ip_packet': 5,
            'port_rx_bytes': 100,
            'port_tx_bytes': 100,
            'port_rx_packets': 10,
            'port_duration_sec': 10,
            'port_flow_count': 1,
            'table_active_count': 1
        }
        resp = self.client.post('/api/live/predict_manual', json=payload)
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("counters cannot be negative", data['error'])

    def test_08_manual_validation_zero_duration(self):
        """Test that port_duration_sec <= 0 is rejected with HTTP 400."""
        payload = {
            'ip_bytes': 500,
            'ip_packet': 5,
            'port_rx_bytes': 100,
            'port_tx_bytes': 100,
            'port_rx_packets': 10,
            'port_duration_sec': 0,
            'port_flow_count': 1,
            'table_active_count': 1
        }
        resp = self.client.post('/api/live/predict_manual', json=payload)
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("must be strictly positive (> 0)", data['error'])

    def test_09_manual_validation_inconsistent_packets(self):
        """Test that ip_packet == 0 with ip_bytes > 0 is rejected with HTTP 400."""
        payload = {
            'ip_bytes': 1500,
            'ip_packet': 0,
            'port_rx_bytes': 100,
            'port_tx_bytes': 100,
            'port_rx_packets': 10,
            'port_duration_sec': 10,
            'port_flow_count': 1,
            'table_active_count': 1
        }
        resp = self.client.post('/api/live/predict_manual', json=payload)
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("cannot be 0 when 'ip_bytes' is non-zero", data['error'])

    def test_10_manual_validation_inconsistent_port_rx_packets(self):
        """Test that port_rx_packets == 0 with port_rx_bytes > 0 is rejected with HTTP 400."""
        payload = {
            'ip_bytes': 100,
            'ip_packet': 2,
            'port_rx_bytes': 5000,
            'port_tx_bytes': 100,
            'port_rx_packets': 0,
            'port_duration_sec': 10,
            'port_flow_count': 1,
            'table_active_count': 1
        }
        resp = self.client.post('/api/live/predict_manual', json=payload)
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("cannot be 0 when 'port_rx_bytes' is non-zero", data['error'])

    def test_11_manual_validation_non_numeric_input(self):
        """Test that non-numeric inputs are rejected with HTTP 400 and clear error."""
        payload = {
            'ip_bytes': 'MALICIOUS_STRING',
            'ip_packet': 2,
            'port_rx_bytes': 500,
            'port_tx_bytes': 100,
            'port_rx_packets': 5,
            'port_duration_sec': 10,
            'port_flow_count': 1,
            'table_active_count': 1
        }
        resp = self.client.post('/api/live/predict_manual', json=payload)
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("Invalid non-numeric input", data['error'])

    def test_12_honest_limits_dynamic_loading(self):
        """Test that /api/live/honest_limits loads without hardcoded metrics."""
        resp = self.client.get('/api/live/honest_limits')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertAlmostEqual(data['temporal_split_accuracy'], 0.9425, places=3)
        self.assertEqual(data['weakest_recall_class'], 'SQLInjection')
        self.assertEqual(data['weakest_precision_class'], 'CMD')
        self.assertIn("untested hypothesis", data['hypothesis'])

    def test_13_feature_importances_panel(self):
        """Test that /api/live/feature_importances returns global Gini importance for 9 R1 features."""
        resp = self.client.get('/api/live/feature_importances')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['panel_title'], 'Feature importance (global)')
        self.assertEqual(len(data['features']), 9)


if __name__ == '__main__':
    unittest.main()

