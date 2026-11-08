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

The 1,178 duplicates are the whole story. The raw data is a sequence of OpenFlow counter
snapshots taken as switch uptime advances. Consecutive rows describe the same flows a
moment apart, so their feature vectors are often identical or near-identical. A random
shuffle puts some of those near-twins in train and their partners in test. The model then
"recognises" the test row instead of generalising to it. 1.26% of the test set was a
literal copy of a training row, and the surrounding rows were close enough to do the same
job. That is enough to carry accuracy to 100%.

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

What the caveat does change is the confidence attached to the *margin*. CV says Logistic
Regression is 0.10 macro F1 ahead of KNN; the test set says 0.20 accuracy ahead. Those are
different numbers from different estimates, and neither is a precise measurement.

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

---

## 6. Next experiments

- **Rate features.** Derive bytes/sec and packets/sec from the duration columns
  (`port_duration_sec`, `ip_duration`) to replace cumulative counters that grow with time,
  then re-run the temporal comparison. This is the direct test of the section 2 hypothesis.
- **Live Mininet traffic.** Generate traffic in a live topology and classify it with the
  trained models, to see whether offline accuracy survives contact with traffic the models
  were not built from.
