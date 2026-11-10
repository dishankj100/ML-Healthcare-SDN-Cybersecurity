# Findings

Plain-English summary of what the honest evaluation actually shows. Every number below
comes from a file in `results/` or from a script run against `Archieve/`. Nothing here is
estimated.

---

## 1. What changed

The old evaluation reported **100% accuracy**. The new one does not.

| Split | Accuracy | Macro F1 | Test rows | Test rows duplicating a train row |
|---|---|---|---|---|
| Old random 80/20 | 1.0000 | 1.0000 | 93,659 | 1,178 (1.26%) |
| Temporal 70/30, 200-row gap | 0.3978 | 0.3774 | 139,233 | 0 (0.00%) |

Source: `results/leakage_comparison.csv`.

The 1,178 duplicates are exact matches only. To measure how close test rows sit to their
nearest training row in general, both splits were scaled on their own training set and a
20,000-row random sample of each test set was measured for Euclidean distance to the nearest
training row across the nine fixed features. Source:
`results/nearest_neighbor_distance.csv`.

| Split | Median distance | 90th percentile | Share at distance 0 | Share under 0.01 | Share under 0.1 |
|---|---|---|---|---|---|
| Old random 80/20 | 0.001734 | 0.022427 | 1.28% (256 rows) | 78.54% | 98.86% |
| Temporal 70/30, 200-row gap | 0.254688 | 1.661420 | 0.00% (0 rows) | 2.15% | 30.60% |

The median test row under the random split sits 0.001734 away from a training row, against
0.254688 under the temporal split, roughly two orders of magnitude further. 78.54% of
random-split test rows lie within 0.01 of a training row, against 2.15% under the temporal
split.

What this supports: under a random shuffle, most test rows have a training row that is
nearly identical to them. Under the temporal split, they do not. That is a measured property
of the two splits.

What it does not establish: that this proximity is what produced 100% accuracy. The distance
measurement and the accuracy measurement are separate observations, and no experiment here
isolates one as the cause of the other. The causal claim is an inference, not a result.

The temporal split removes the mechanism: train on the first 70% of each class's timeline,
purge 200 rows, test on what remains. Duplicate test rows drop to zero, and Random Forest
accuracy drops from 1.0000 to 0.3978.

Note the drop is measured on Random Forest in both cases, so the comparison is
like-for-like.

---

## 2. The model-family gap

On the temporal split the ranking inverts. The models that normally lose, win:

| Model | CV macro F1 | Test accuracy |
|---|---|---|
| Logistic Regression (scaled) | 0.9847 | **0.9598** |
| KNN (scaled) | 0.8814 | 0.8185 |
| Naive Bayes | 0.5635 | 0.6442 |
| LightGBM | 0.6095 | 0.5412 |
| XGBoost | 0.5225 | 0.5284 |
| Decision Tree | 0.4847 | 0.4372 |
| Random Forest | 0.4648 | 0.3978 |
| AdaBoost | 0.4112 | 0.3883 |

Source: `results/metrics.csv`.

Scaled Logistic Regression beats every tree model by a wide margin. That is backwards from
the usual expectation and it needs an explanation, not a shrug.

**The drift diagnostics are consistent with one explanation.** `results/feature_drift.csv`
records, per class and per feature, the share of test rows whose value exceeds the maximum
seen in training. Three features dominate:

| Feature | Classes where 100% of test rows exceed the train max |
|---|---|
| `port_rx_packets` | BruteForce, CMD, Probe, SQLInjection, Smaba, VNC |
| `port_rx_bytes` | BruteForce, CMD, Probe, SQLInjection, Smaba, VNC |
| `port_tx_bytes` | BruteForce, CMD, Probe, SQLInjection, Smaba, VNC |

For those same six classes the remaining six features are at or near 0.00% drift. Normal
sits at 74.03% on `port_tx_bytes`, TCPDDOS at 49.99% on `port_rx_packets`, UDPDDOS at 50.00%
on `port_rx_packets` and `port_rx_bytes`. Source: `results/class_drift_summary.csv` and
`results/feature_drift.csv`.

UDPDDOS is worth stating precisely because it is the one class where a summary could easily
overstate the case: its highest drift figure is **50.00%**, on `ip_bytes`, `ip_packet`,
`port_rx_packets` and `port_rx_bytes`. No UDPDDOS feature reaches 100%. Verified directly
against `results/feature_drift.csv`.

Those three features are cumulative counters. They only ever increase as the switch stays
up, so later rows are guaranteed to sit above the training range. A decision tree can only
split at thresholds it saw during training; anything above its highest observed value falls
into the topmost leaf and inherits whatever label that leaf held. It cannot represent
"more than I have ever seen". A scaled linear model can extrapolate past the training range,
and KNN simply assigns the nearest neighbour regardless of how far outside the range the
point lies.

**This is a hypothesis, and these diagnostics do not prove it.** The drift table shows the
counters do exceed the training range; it does not show that this is what costs the trees
their accuracy. Nothing here isolates the mechanism from other differences between the model
families. What would test it: replace the cumulative counters with rate features that do not
grow with time, for example bytes per second and packets per second derived from the
duration columns, then re-run the same temporal comparison. If the tree models recover and
the gap closes, the extrapolation explanation holds. If the gap survives, it is something
else.

---

## 3. Generalization to unseen traffic

Four models were trained on the temporal training set only, then asked to classify traffic
they had never seen. Full output: `results/unseen_traffic_all_models.csv`.

Percent of each file labelled **Normal**:

| File | Logistic Regression | KNN | LightGBM | Random Forest |
|---|---|---|---|---|
| `normal_iperf.csv` (36,076 rows) | 16.26% | 0.01% | 0.22% | 0.25% |
| `normal_internet1.csv` (30,419 rows) | 8.97% | 10.26% | 61.58% | 93.27% |
| `normal_internet2.csv` (4,572 rows) | 64.65% | 75.11% | 61.66% | 97.16% |
| `normal_internet3.csv` (30,224 rows) | 9.62% | 11.18% | 60.90% | 93.49% |

Label distribution on `ddos_attack_scapy_new.csv` (29,257 rows):

| Model | Distribution |
|---|---|
| Logistic Regression | UDPDDOS 100.00% |
| KNN | SQLInjection 99.44%, UDPDDOS 0.51%, Probe 0.06% |
| LightGBM | **Normal 98.12%**, CMD 1.84%, SQLInjection 0.04% |
| Random Forest | SQLInjection 96.54%, Probe 2.90%, CMD 0.39%, Normal 0.17% |

Read this honestly, because it is not good news for any model:

- **No model handles `normal_iperf.csv`.** The best is Logistic Regression at 16.26% Normal;
  the other three label essentially all of it as an attack. Random Forest calls 98.81% of it
  SQLInjection. This is benign traffic from a load generator and every model fails on it.
- **The internet traces are inconsistent across models.** Random Forest does best (93.27% to
  97.16% Normal), Logistic Regression and KNN do worst (8.97% to 11.18% on traces 1 and 3).
  The ordering here is the reverse of the temporal test set, where Logistic Regression won.
- **The scapy DDoS file gets four different answers.** Logistic Regression calls it all
  UDPDDOS, KNN calls it almost all SQLInjection, Random Forest calls it mostly SQLInjection,
  and LightGBM calls 98.12% of it Normal. Four models, four incompatible verdicts, on the
  same file.

**Causes are not asserted here, because nothing measured supports a specific one.**
`normal_iperf.csv` being labelled SQLInjection by Random Forest is a fact about the output,
not an explanation. The one observation that is safe to state: these files are a different
traffic source from `normal_ditg.csv`, the only normal traffic any of these models were
trained on. A load generator and a real internet trace do not look like an SDN testbed's
baseline. Whether that source difference is what drives the misclassification is an
**untested hypothesis**. Testing it would mean training on a mix of normal sources and
re-running, or measuring which features separate `normal_ditg.csv` from the unseen files.

The same applies to the scapy labels. The disagreement between models is the finding; the
reason for it is not established here.

---

## 4. Model selection caveat

Picking the model with the best **test** accuracy is an optimistic way to choose, because the
test set has then been used to make the choice and is no longer held out.

Using **CV scores only** (`CV_f1_macro`, tuned with TimeSeriesSplit on the training set), the
ranking is Logistic Regression 0.9847, KNN 0.8814, LightGBM 0.6095, Naive Bayes 0.5635,
XGBoost 0.5225, Decision Tree 0.4847, Random Forest 0.4648, AdaBoost 0.4112.

**The choice does not differ.** Logistic Regression is first on CV and first on test accuracy.
So the headline result survives this particular objection, which is worth saying plainly
rather than hedging.

What the caveat does change is the confidence attached to the *margin*, and the metric has to
be named. Computed from `results/metrics.csv`: Logistic Regression leads KNN by **0.1413 on
test accuracy** (0.9598 vs 0.8185) and by **0.2005 on macro F1** (0.9496 vs 0.7491). On CV
macro F1 the gap is 0.1033 (0.9847 vs 0.8814). Those are three different estimates of the
same comparison, and they do not agree with each other.

---

## 5. What these numbers do NOT show

- **They do not show that any model detects attack behaviour.** The task measured here is
  classifying rows of a labelled dataset into the same nine categories they were drawn from.
  High accuracy means the model reproduces the dataset's labels, not that it identifies an
  intrusion in progress.
- **They do not show that results transfer to live traffic.** Every number comes from offline
  CSVs captured in one testbed. The unseen-traffic results in section 3 are the closest thing
  to a transfer test in this work, and they are poor.
- **They do not show that application-layer attacks are visible in flow counters at all.**
  SQLInjection, CMD, Samba and VNC are application-layer behaviours. The nine features are
  OpenFlow port and table counters: bytes, packets, flow counts, active entries. Nothing in
  that feature set describes payload content, query strings, shell commands or protocol
  semantics. A model can separate these classes in this dataset because the traffic was
  generated by separate scripted scenarios with different volume and timing profiles, not
  because the counters reveal the attack. Whether flow counters carry any genuine
  application-layer signal is untested here.
- **They do not show that the models learned attack behaviour rather than capture identity.**
  Each class comes from a single capture file, so class and capture session are perfectly
  confounded: every Normal row is from `normal_ditg.csv`, every VNC row from
  `attack_vnc.csv`, and so on. The temporal split runs *within* each file, which removes
  leakage across time but does not remove session-specific counter levels. Each capture
  session began with its own switch uptime and its own traffic volume, and those levels are
  a property of the session, not of the attack. A model can therefore separate the nine
  classes using session identity alone.

  This is directly relevant to the headline result. **Logistic Regression's 0.9598 temporal
  accuracy may partly reflect this confound rather than attack detection** — a linear model
  on cumulative counters can separate sessions by their offset. Its poor unseen-traffic
  results are consistent with that reading: it scored 8.97% to 16.26% Normal on traces 1, 3
  and iperf, where the session offsets differ from anything in training. **This is an
  untested hypothesis.** Nothing here measures how much of the accuracy is session identity.
  Separating the two would need multiple capture sessions per class.

---

## 6. Next experiments

- **Rate features.** Derive bytes/sec and packets/sec from the duration columns
  (`port_duration_sec`, `ip_duration`) to replace cumulative counters that grow with time,
  then re-run the temporal comparison. This is the direct test of the section 2 hypothesis.
- **Live Mininet traffic.** Generate traffic in a live topology and classify it with the
  trained models, to see whether offline accuracy survives contact with traffic the models
  were not built from.

---

## 7. Rate features and confound checks

Two new feature sets were built and evaluated on the same temporal split (first 70%, 200-row
gap, last 30%, no shuffling), with the same eight models and the same train-only tuning.

**R1** uses only single-row features, no history and no `ip_duration`:
`ip_bytes`, `ip_packet`, `ip_bytes/ip_packet`, `port_rx_bytes/port_duration_sec`,
`port_tx_bytes/port_duration_sec`, `port_rx_packets/port_duration_sec`,
`port_rx_bytes/port_rx_packets`, `port_flow_count`, `table_active_count`.

**R2** uses backward-looking per-flow deltas keyed on `(src, dst, in_port)`, divided by the
change in `port_duration_sec` between consecutive observations of that key. `src` and `dst`
are used for keying only and are never model features. Deltas were computed on each whole
file in original row order and then split, so gap rows serve as history but belong to neither
set. Rows with zero time change or a negative delta were dropped; retention stayed between
97.82% (UDPDDOS) and 100.00% (VNC), so no class came near the 30% loss threshold.

**A note on what the R1 rates mean.** `port_duration_sec` is switch uptime, not a per-row
interval. So `port_rx_bytes / port_duration_sec` is a **lifetime average since the switch came
up**, not an instantaneous rate. It still grows slowly with time, just far less than the raw
counter. Only R2's deltas are true interval rates.

### Did the tree models recover?

Yes, and substantially. Test accuracy:

| Model | Original 9 counters | R1 | R2 |
|---|---|---|---|
| Decision Tree | 0.4372 | 0.7581 | 0.8101 |
| Random Forest | 0.3978 | 0.9452 | 0.8285 |
| XGBoost | 0.5284 | 0.8899 | 0.7753 |
| LightGBM | 0.5412 | 0.8476 | 0.8430 |
| AdaBoost | 0.3883 | 0.8241 | 0.4109 |

Random Forest moves from 0.3978 to 0.9452 under R1, a gain of 0.5474. Decision Tree gains
0.3209 under R1 and 0.3729 under R2. On R1 the trees are no longer the worst family in the
table.

### Did the Logistic Regression advantage shrink or vanish?

It depends heavily on whether features are log-transformed, though on per-flow deltas (R2) the linear model trails tree ensembles.

With `max_iter=5000` (which eliminates all `ConvergenceWarning`s), Logistic Regression converges cleanly:
- On **R1**: raw rates converge in 76 iterations (0.9515 accuracy, 0.9359 macro F1); with `log1p` applied to rate features (`ip_bytes_per_packet`, `port_rx_bytes_rate`, `port_tx_bytes_rate`, `port_rx_packets_rate`, `port_rx_bytes_per_packet`), it converges in 96 iterations to **0.9999** accuracy and **0.9999** macro F1.
- On **R2**: raw rates converge in 430 iterations to **0.7259** accuracy (0.6697 macro F1), up from 0.6912 when iterations were capped at 100; with `log1p` on delta rates, it converges in 375 iterations to **0.6718** accuracy (0.6068 macro F1).

| Model | Original 9 counters | R1 (raw) | R1 (log1p) | R2 (raw, converged) | R2 (log1p, converged) |
|---|---|---|---|---|---|
| Logistic Regression | 0.9598 | 0.9515 | 0.9999 | 0.7259 | 0.6718 |
| Random Forest | 0.3978 | 0.9452 | — | 0.8286 | — |
| LightGBM | 0.5412 | 0.8476 | — | 0.8342 | — |
| KNN | 0.8185 | 0.9576 | — | 0.7688 | — |

Under R1 with log1p rates, Logistic Regression recovers completely to 0.9999. Under R2, full convergence raises Logistic Regression to 0.7259, but it still trails Random Forest (0.8286) and LightGBM (0.8342) by 10–11 percentage points. Thus, the linear model's massive advantage on cumulative counters does not hold on per-flow interval rates (R2), where non-linear tree partitions capture the delta relationships more effectively.

### Is the comparison fair?

Yes, and this needed checking. R2 drops rows, so its test set is smaller and different. To
separate the feature change from the row change, the original nine cumulative counters were
re-evaluated on **exactly the R2 retained rows**:

| Model | 9 counters, full test | 9 counters, R2 rows only | R2 features, R2 rows |
|---|---|---|---|
| Logistic Regression | 0.9598 | 0.9904 | 0.6912 |
| Random Forest | 0.3978 | 0.3848 | 0.8285 |
| KNN | 0.8185 | 0.8176 | 0.7641 |
| LightGBM | 0.5412 | 0.5943 | 0.8430 |

On identical rows, the cumulative counters score **0.9904** with Logistic Regression against
**0.6912** for the R2 deltas. So R2's lower accuracy is not an artifact of the smaller test
set; the deltas genuinely carry less separable signal than the raw counters do. Equally,
Random Forest's R2 gain (0.3848 to 0.8285) is a real feature effect, not row selection.

### Did the unseen-normal results improve?

Mixed, and mostly not in the way that would matter.

Percent labelled Normal on the internet traces:

| Model | Original (9 counters) | R1 | R2 |
|---|---|---|---|
| Random Forest | 93.27 / 97.16 / 93.49 | 100.00 / 100.00 / 100.00 | 75.67 / 75.48 / 75.39 |
| Logistic Regression | 8.97 / 64.65 / 9.62 | 100.00 / 99.98 / 100.00 | 71.02 / 71.56 / 70.40 |

On `normal_iperf.csv`, the file every model failed before:

| Model | Original | R1 | R2 |
|---|---|---|---|
| Random Forest | 0.25 | 0.01 | 48.01 |
| Logistic Regression | 16.26 | 19.84 | 16.89 |
| Decision Tree | 0.23 | 0.05 | 40.53 |

R2 improves iperf markedly for the trees (0.25 to 48.01 for Random Forest) but still labels
about half of it as an attack. R1 makes the internet traces look perfect while leaving iperf
broken, which is not a coherent improvement.

The scapy DDoS file remains incoherent across models. Under R1, Random Forest, XGBoost and
LightGBM all assign Probe to 100.00% of rows, while KNN assigns UDPDDOS to 99.56% and Logistic
Regression splits Normal 49.18% / UDPDDOS 47.30%. Under R2, Random Forest, Logistic
Regression, XGBoost and LightGBM assign Normal to 100.00%, while KNN assigns SQLInjection to
98.75%. No measurement here explains the disagreement.

### What the confound baselines imply

Source: `results/rate_features/confound_baselines.csv`.

| Baseline | Test accuracy | Macro F1 |
|---|---|---|
| Chance (uniform, 1/9) | 0.1111 | 0.1111 |
| Majority class (UDPDDOS, 18.03% of test) | 0.1803 | 0.0340 |
| Logistic Regression on `port_duration_sec` only | 0.1617 | 0.0893 |
| Random Forest on `port_duration_sec` only | 0.0874 | 0.0414 |
| Logistic Regression on `table_active_count` only | 0.5947 | 0.4308 |
| **Random Forest on `table_active_count` only** | **0.6549** | **0.5894** |
| Random Forest on 9 cumulative counters | 0.3978 | 0.3774 |
| Logistic Regression on 9 cumulative counters | 0.9598 | 0.9496 |

Three things follow, and they are uncomfortable.

1. **A single gauge feature beats the full nine-feature Random Forest.** `table_active_count`
   alone scores 0.6549 against 0.3978 for all nine counters. Adding eight more features made
   Random Forest substantially worse, which is the opposite of what a useful feature set does.
2. **`port_duration_sec` is nearly worthless on its own.** 0.1617 and 0.0874 are at or below
   the majority-class baseline of 0.1803. Switch uptime alone does not identify the class.
3. **The class signal is concentrated in one gauge.** `table_active_count` is the number of
   active flow entries in the switch table. It is a property of how much traffic the scenario
   generated, not of what the traffic was doing. A model scoring 0.6549 from that one number
   is consistent with the hypothesis that it is reading traffic volume and session shape rather
   than attack behaviour.

This is consistent with the capture-session confound described in section 5, but it does not
prove it. Nothing here measures how much of the 0.9598 Logistic Regression accuracy is
session identity rather than attack behaviour. What the baselines do establish is that a
large share of the achievable accuracy is available from a single volume gauge, which sets a
floor under how much of the result can be attributed to the attack signatures themselves.

### Limitation: R2 needs two consecutive snapshots

R2's deltas require the previous observation of the same `(src, dst, in_port)` key. That
means a row cannot be scored until a second snapshot of that flow has arrived. For a live
capture that is a one-polling-interval delay. For any **manual-entry mode**, where a row is
typed or pasted in one at a time with no history, R2 cannot be computed at all — only R1's
single-row features are available. R2 is therefore not a drop-in replacement for the current
feature set in every deployment context.

### Audit of the 0.9999 R1 Logistic Regression result

Source: `results/rate_features/r1_lr_audit.csv`.

Because an accuracy of 0.9999 on a temporal split is extraordinarily high, an audit was conducted across five checks:

1. **Per-class recall & confusion matrix:** Out of 139,233 test rows, exactly **13 rows (0.0093%)** are misclassified: 8 TCPDDOS misclassified as Smaba, 3 VNC as Smaba, 1 CMD as Normal, and 1 VNC as TCPDDOS. Every class has recall $\ge 0.9995$ (seven classes at 1.000000).
2. **Single-feature accuracy:** No single R1 feature achieves high accuracy on its own. LR accuracy on individual features ranges from 0.2649 (`ip_bytes_per_packet`) to 0.6155 (`port_rx_bytes_per_packet`) and 0.5947 (`table_active_count`). For Random Forest, the highest single-feature accuracy is 0.6991 (`ip_bytes`) and 0.6557 (`table_active_count`).
3. **Drop-one ablation:** Dropping any single feature leaves LR test accuracy above 0.9991, with the sole exception of `port_tx_bytes_rate`, where dropping it reduces accuracy slightly to **0.9570** ($\Delta = -0.0429$). The 0.9999 score does not depend on any fragile single feature.
4. **Drift and nearest-neighbour distance in R1 space:**
   - In R1 space, 100% of test rows still exceed train maximums for BruteForce, CMD, SQLInjection, and UDPDDOS, but Normal (0.02%), Smaba (0.00%), and VNC (0.15%) have near-zero upper-bound drift.
   - For a 20,000-row test sample, the **median nearest-neighbour distance drops to 0.0419** (down from 0.2547 on the original counters), with **81.40% of test points falling within distance < 0.1** of a training row (up from 30.60%). Because R1 divides cumulative counters by switch uptime (`port_duration_sec`), it computes capture-lifetime averages that stabilize around fixed constants for each session, pulling test rows into tight Euclidean clusters around their respective training rows.
5. **Unseen traffic:**
   - On the three internet traces, the model labels **100.00% as Normal** (only 1 false positive out of 65,215 total rows).
   - On `normal_iperf.csv`, the model labels only **26.23% as Normal**, classifying **72.46% (26,142 rows) as BruteForce**.
   - On `ddos_attack_scapy_new.csv`, it classifies **100.00% (29,257 rows) as UDPDDOS**.

**What these numbers show:** The 0.9999 accuracy is mathematically genuine under the temporal split and resilient to feature ablation, but it is heavily aided by R1's lifetime-averaging formulation, which clusters test points closely around training points in normalized space (median 1-NN distance 0.0419 vs 0.2547).

**What the audit cannot establish:** The audit cannot prove that this model has learned generalized multi-vector attack mechanics rather than session-specific traffic profiles. The fact that high-throughput clinical iperf traffic is 72.5% misclassified as BruteForce demonstrates that the model remains vulnerable to false positives when presented with benign traffic patterns that differ in volume or packet rates from the single `normal_ditg.csv` capture.

### What section 7 does not show

- It does not show that the rate features detect attack behaviour better. R2 scored *lower*
  than the cumulative counters on identical rows.
- It does not show that the section 2 extrapolation hypothesis was correct. The trees did
  recover, which is consistent with it, but R1's lifetime-average rates still grow with time
  and the confound baselines offer a competing explanation for the same numbers.
- It does not identify why the models disagree on the scapy file.
