"""
HealthGuard AI - Automated Verification & Test Suite
Runs end-to-end validation of all 6 modules, APIs, database persistence, and ML predictions.
"""

import sys
import unittest
import numpy as np

try:
    import app
    from soc_engine import (
        soc_engine,
        SCENARIOS,
        HOSPITAL_TOPOLOGY,
        ACTUAL_EVALUATION_RESULTS,
        ATTACK_CLASSES
    )
except ImportError as e:
    print(f"FAILED TO IMPORT: {e}")
    sys.exit(1)


class TestHealthGuardSOC(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = app.app.test_client()

    def test_01_core_routes_render(self):
        """Verify all HTML endpoints return 200 OK."""
        routes = ['/', '/soc', '/classic', '/home', '/about', '/notebook', '/login', '/logon']
        for r in routes:
            res = self.client.get(r)
            self.assertEqual(res.status_code, 200, f"Route {r} failed with status {res.status_code}")
        print("[OK] Test 01 Passed: All HTML routes render successfully (200 OK).")

    def test_02_threat_stats_api(self):
        """Verify Module 1 stats API returns expected schema."""
        res = self.client.get('/api/stats')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('total_incidents_logged', data)
        self.assertIn('active_threats', data)
        self.assertIn('system_health_score', data)
        self.assertIn('attack_distribution', data)
        print("[OK] Test 02 Passed: Module 1 Threat Stats API returns valid telemetry data.")

    def test_03_all_nine_scenarios(self):
        """Verify Module 2 runs genuine inference across all 9 attack/normal scenarios."""
        res = self.client.get('/api/scenarios')
        self.assertEqual(res.status_code, 200)
        scenarios = res.get_json()
        self.assertEqual(len(scenarios), 9)

        expected_classes = {
            'normal': 2,
            'tcp_ddos': 6,
            'udp_ddos': 7,
            'sqli': 5,
            'bruteforce': 0,
            'port_scan': 3,
            'cmd_injection': 1,
            'samba': 4,
            'vnc': 8
        }

        for sc_id, exp_cls in expected_classes.items():
            res_pred = self.client.post('/api/predict_soc', json={'scenario_id': sc_id})
            self.assertEqual(res_pred.status_code, 200, f"Scenario {sc_id} failed: {res_pred.get_data(as_text=True)}")
            data = res_pred.get_json()
            self.assertEqual(data['class_id'], exp_cls, f"Scenario {sc_id} predicted {data['class_id']}, expected {exp_cls}")
            self.assertGreaterEqual(data['confidence'], 90.0)
            self.assertIn('explanation', data)
            print(f"  - Scenario '{sc_id}' -> Class {data['class_id']} ({data['attack_name']}) at {data['confidence']}% conf")

        print("[OK] Test 03 Passed: All 9 Attack Simulation scenarios produce ground-truth predictions.")

    def test_04_explainable_ai_shap(self):
        """Verify Module 3 provides global importances and TreeSHAP values."""
        # Global
        res_g = self.client.get('/api/explain/global')
        self.assertEqual(res_g.status_code, 200)
        global_imp = res_g.get_json()
        self.assertEqual(len(global_imp), 9)
        self.assertEqual(global_imp[0]['feature'], 'port_tx_bytes')

        # Local
        sample_features = SCENARIOS['sqli']['features']
        res_l = self.client.post('/api/explain/local', json={'features': sample_features, 'class_id': 5})
        self.assertEqual(res_l.status_code, 200)
        local_exp = res_l.get_json()
        self.assertIn('top_contributors', local_exp)
        self.assertEqual(len(local_exp['top_contributors']), 9)
        self.assertTrue(local_exp['is_exact_shap'])
        print("[OK] Test 04 Passed: Module 3 Explainable AI (TreeSHAP) returns accurate feature attributions.")

    def test_05_incident_response_lifecycle(self):
        """Verify Module 4 incident creation, triage actions, and audit trail."""
        # 1. Trigger an attack to generate an incident
        res_pred = self.client.post('/api/predict_soc', json={'scenario_id': 'tcp_ddos'})
        inc_data = res_pred.get_json()['incident_created']
        self.assertIsNotNone(inc_data)
        inc_id = inc_data['incident_id']

        # 2. Block IP
        res_action = self.client.post(f'/api/incidents/{inc_id}/action', json={'action': 'BLOCK_IP', 'operator': 'Test_Unit'})
        self.assertEqual(res_action.status_code, 200)
        self.assertTrue(res_action.get_json()['success'])
        self.assertEqual(res_action.get_json()['status'], 'MITIGATED')

        # 3. Check Audit Log
        res_aud = self.client.get('/api/audit-log')
        self.assertEqual(res_aud.status_code, 200)
        aud_list = res_aud.get_json()
        latest = aud_list[0]
        self.assertEqual(latest['incident_id'], inc_id)
        self.assertEqual(latest['action'], 'BLOCK_IP')

        # 4. Resolve incident
        res_res = self.client.post(f'/api/incidents/{inc_id}/action', json={'action': 'RESOLVE'})
        self.assertEqual(res_res.status_code, 200)
        self.assertEqual(res_res.get_json()['status'], 'RESOLVED')
        print("[OK] Test 05 Passed: Module 4 Incident Response lifecycle (Triage -> Block -> Audit -> Resolve) verified.")

    def test_06_hospital_topology(self):
        """Verify Module 5 topology nodes and connections."""
        res = self.client.get('/api/topology')
        self.assertEqual(res.status_code, 200)
        topo = res.get_json()
        self.assertEqual(len(topo['nodes']), 12)
        self.assertEqual(len(topo['links']), 11)
        # Check critical assets
        node_ids = [n['id'] for n in topo['nodes']]
        for req in ['sdn-controller', 'firewall', 'sdn-switch', 'icu-monitor', 'ehr-server', 'infusion-pump']:
            self.assertIn(req, node_ids)
        print("[OK] Test 06 Passed: Module 5 Hospital Network Topology loaded with all 12 assets.")

    def test_07_model_evaluation(self):
        """Verify Module 6 actual test-set confusion matrix and benchmarks."""
        res = self.client.get('/api/evaluation')
        self.assertEqual(res.status_code, 200)
        ev = res.get_json()
        self.assertEqual(ev['summary']['test_set_size'], 24707)
        self.assertAlmostEqual(ev['summary']['accuracy'], 0.9884, places=3)
        self.assertEqual(len(ev['confusion_matrix']), 9)
        self.assertEqual(len(ev['benchmark_comparison']), 9)
        print("[OK] Test 07 Passed: Module 6 Model Evaluation returns ground-truth metrics.")

    def test_08_legacy_prediction_form(self):
        """Verify backward compatibility of original POST /predict endpoint."""
        # Test sample representing Normal flow
        data = {str(i): SCENARIOS['normal']['features'][i] for i in range(9)}
        res = self.client.post('/predict', data=data)
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn('Normal', html)
        print("[OK] Test 08 Passed: Legacy POST /predict form submission works seamlessly.")


if __name__ == '__main__':
    unittest.main()
