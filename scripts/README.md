# Offline Evaluation & Diagnostic Scripts

This directory contains the standalone offline diagnostic and experiment scripts used to audit data leakage, build rate features, evaluate confound baselines, and perform honest temporal evaluations on the MCAD-SDN healthcare dataset.

## Script Manifest

- `_diag_order.py`: Verifies that OpenFlow switch uptime (`port_duration_sec`) is monotonically non-decreasing along raw CSV row order across all capture files.
- `_step1_fix.py`: Corrects metric calculation order to `metric(y_true, y_pred)` and executes the baseline temporal split evaluation across the original 9 cumulative counters.
- `_step2_keys.py`: Analyzes `(src, dst, in_port)` flow key uniqueness, lifespan, and collision distributions across classes for R2 delta keying.
- `_step2_structure.py`: Inspects telemetry schema properties, feature distributions, zero-variance columns, and missing values across raw captures.
- `_step2_unseen_all_models.py`: Evaluates all 8 classifiers against unseen normal traffic (`normal_iperf`, `normal_internet1/2/3`) and unseen attack traffic (`ddos_attack_scapy_new`).
- `_step3_build.py`: Constructs the R1 (single-row lifetime rates) and R2 (per-flow backward deltas keyed by `(src, dst, in_port)`) feature sets from raw OpenFlow captures.
- `_step3_train.py`: Trains and evaluates the 8-model suite on R1 and R2 feature sets using cross-validation.
- `_step4_confound.py`: Computes confound baselines including uniform chance, majority class, `port_duration_sec` alone, and `table_active_count` alone.
- `_step5_final.py`: Runs final offline verification: evaluates Logistic Regression with `max_iter=5000` + `log1p` on rate features, and performs validation-block tuning (85% train / 15% validation) across all 8 models for R1 and R2.
- `audit_r1_lr.py`: Audits the 0.9999 test accuracy of R1 Logistic Regression with log1p across confusion matrix/recall, single-feature evaluations, drop-one ablation, drift/NN distance, and unseen traffic.
- `compute_r1_nn_baseline.py`: Computes nearest-neighbour distances (20,000-row sample) strictly within R1 log1p space for random 80/20 and temporal 70/30 splits for valid same-space comparison.
- `train_live_model.py`: Trains Random Forest (100 trees, random_state=42) on R1 single-row rate features on temporal train set; saves live_model.joblib and results/live_replay/model_metrics.csv.
