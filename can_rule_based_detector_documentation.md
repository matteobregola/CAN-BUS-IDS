# CAN Rule-Based Detector Documentation

Documentation for `can_rule_based_detector_simplified_split.ipynb`.

This document explains how the simplified CAN bus intrusion detection notebook works. It covers the current notebook pipeline only. It does not include the additional CSV feature-export wrapper discussed afterward.

---

## 1. Purpose of the notebook

The notebook implements a rule-based intrusion detection system for CAN bus traffic.

The design is based on two separated stages:

1. **Training / calibration stage**
   - Uses a benign-only CAN dataset.
   - Learns what normal traffic looks like.
   - Calculates global and per-CAN-ID thresholds.
   - Saves those thresholds into a JSON detector profile.

2. **Evaluation stage**
   - Loads the saved detector profile.
   - Extracts the same compact feature set from one or more evaluation files.
   - Applies explicit rules for common CAN attack families.
   - Prints predictions, rule activations, suspicious rows, and metrics when labels are available.

The main goal is to avoid retraining each time an evaluation file changes. Once the benign profile is saved, the evaluation cell can be rerun repeatedly with different files.

---

## 2. High-level architecture

The notebook is organized into the following blocks:

| Notebook section | Main responsibility |
|---|---|
| User Configuration | Defines file paths, column names, feature settings, and rule settings. |
| Constants and Configuration | Defines CAN limits, column configuration, and output columns. |
| CSV Loading and Column Standardization | Reads CSV files and converts different schemas into a canonical format. |
| Preprocessing | Parses timestamps, CAN IDs, payloads, DLC, and diagnostic fields. |
| Compact Feature Extraction | Generates only the features used by the rules. |
| End-to-End Feature Wrapper | Runs standardization, preprocessing, and feature extraction together. |
| Rule-Based Detector | Learns benign profiles, saves/loads JSON profiles, and predicts attacks. |
| Evaluation Helpers | Normalizes labels and computes metrics. |
| Pipeline Functions | Provides user-facing training and evaluation functions. |
| Training Stage | Optional cell that creates or updates the saved profile. |
| Evaluation Stage | Reusable cell that evaluates files using the saved profile. |

---

## 3. User configuration

The main configuration cell defines the values that the user normally edits.

### File paths

```python
TRAINING_FILE = "benign_training_dataset.csv"
DETECTOR_PROFILE_FILE = "can_detector_profile.json"
EVALUATION_FILES = ["evaluation_dataset_with_attacks.csv"]
```

- `TRAINING_FILE` is the benign-only training CSV used to calibrate the detector.
- `DETECTOR_PROFILE_FILE` is the JSON file where thresholds and learned normal behavior are saved.
- `EVALUATION_FILES` is a list of one or more CSV files to evaluate.

### Execution flags

```python
RUN_TRAINING_STAGE = False
RUN_EVALUATION_STAGE = True
```

- Set `RUN_TRAINING_STAGE = True` only when training or updating the detector profile.
- Set it back to `False` when repeatedly evaluating files.
- `RUN_EVALUATION_STAGE = True` runs the evaluation cell.

### CSV column mapping

```python
TIMESTAMP_COL = "timestamp"
ARBITRATION_ID_COL = "arbitration_id"
DATA_FIELD_COL = "data_field"
LABEL_COL = "attack"
BYTE_COLS = None
```

These values map the user's CSV columns to the canonical columns expected by the notebook.

- `TIMESTAMP_COL` is the packet timestamp column.
- `ARBITRATION_ID_COL` is the CAN arbitration ID column.
- `DATA_FIELD_COL` is the payload column.
- `LABEL_COL` is optional and is used only for evaluation metrics.
- `BYTE_COLS` can be used when payload bytes are stored in separate columns instead of one data field.

### Feature extraction settings

```python
MAX_PAYLOAD_BYTES = 8
ROLLING_PACKET_WINDOW = 100
TIME_WINDOW_SECONDS = 1.0
```

- `MAX_PAYLOAD_BYTES` limits how many payload bytes are considered. The default value, 8, matches classical CAN.
- `ROLLING_PACKET_WINDOW` controls rolling ID diversity and entropy features.
- `TIME_WINDOW_SECONDS` controls rate-based features such as packet rate per second.

These settings are saved inside the detector profile during training. Evaluation then reuses the saved values to avoid training/evaluation mismatch.

### Rule calibration settings

```python
HIGH_QUANTILE = 0.995
LOW_QUANTILE = 0.005
MIN_ATTACK_SCORE = 2.0
```

- `HIGH_QUANTILE` is used to learn upper normal thresholds from benign traffic.
- `LOW_QUANTILE` is used to learn lower normal thresholds from benign traffic.
- `MIN_ATTACK_SCORE` is the minimum rule score required to label a packet as an attack.

---

## 4. Canonical input schema

Internally, the notebook standardizes all input files into this canonical schema:

| Canonical column | Meaning |
|---|---|
| `timestamp` | Packet timestamp before parsing. |
| `arbitration_id` | Raw CAN arbitration ID before parsing. |
| `data_field` | Raw payload field before normalization. |
| `__true_label` | Optional preserved true label, used only for metrics. |
| `attack` | Temporary compatibility column, immediately dropped during preprocessing. |

The true label is never used for feature extraction, threshold calibration, or prediction. It is only used later to compute evaluation metrics.

---

## 5. CSV loading and standardization

### `load_can_csv()`

This function reads a CSV file using `pandas.read_csv()` and preserves text-like values as strings. This is important because CAN IDs and payloads may be hexadecimal strings, and automatic numeric conversion could damage formatting.

It supports two modes:

- CSV with header, which is the default.
- CSV without header, where explicit column names are supplied.

### `_build_data_field_from_byte_columns()`

This helper is used when the payload is split across separate byte columns, for example:

```text
byte_0, byte_1, byte_2, ..., byte_7
```

It converts each valid byte to a two-character hexadecimal representation and joins the bytes into a single payload string.

Example:

```text
[1, 10, 255] -> "010AFF"
```

Invalid byte values are skipped.

### `standardize_raw_can_columns()`

This function converts dataset-specific column names into the canonical format.

It checks that the timestamp and arbitration ID columns exist. Then it either:

- Copies the configured payload column, or
- Builds the payload from `BYTE_COLS`.

If a label column exists, it is copied to `__true_label`. This preserved label is not used by the detector itself.

---

## 6. Preprocessing

Preprocessing converts raw CAN packet fields into clean, rule-ready diagnostic columns.

The main function is:

```python
preprocess_can_dataframe(raw_df, max_payload_bytes=CAN_CLASSIC_MAX_BYTES)
```

### 6.1 Timestamp parsing

The notebook creates:

| Column | Meaning |
|---|---|
| `timestamp_raw` | Original timestamp value. |
| `timestamp_seconds` | Numeric timestamp converted with `pd.to_numeric()`. |
| `timestamp_parse_valid` | Boolean flag showing whether timestamp parsing succeeded. |
| `time_from_start_s` | Seconds from the first valid timestamp. |

The dataframe is sorted by `timestamp_seconds` using stable chronological sorting. Equal timestamps keep their original order.

### 6.2 CAN arbitration ID parsing

The helper `_parse_can_identifier()` parses CAN IDs robustly.

Parsing rules:

| Input form | Interpretation |
|---|---|
| `0x123` | Hexadecimal. |
| `123` | Decimal, unless it contains A-F. |
| `1AB` | Hexadecimal because it contains A-F. |
| Invalid value | Converted to `NaN`. |
| Negative or above `0x1FFFFFFF` | Converted to `NaN`. |

Generated columns:

| Column | Meaning |
|---|---|
| `arbitration_id_raw` | Original CAN ID value. |
| `arbitration_id` | Parsed numeric CAN ID. |
| `arbitration_id_parse_valid` | Whether parsing succeeded. |
| `arbitration_id_hex` | Human-readable hexadecimal representation. |

### 6.3 Payload normalization

The helper `_normalize_payload_hex()` cleans payload values.

It performs the following operations:

1. Converts the payload to uppercase text.
2. Removes a leading `0x` if present.
3. Removes common separators: spaces, hyphens, colons, underscores, and commas.
4. Checks whether the result contains only hexadecimal characters.
5. Checks whether the number of nibbles is even.

Generated columns:

| Column | Meaning |
|---|---|
| `data_field_raw` | Original payload value. |
| `payload_hex_normalized` | Clean uppercase payload string. |
| `payload_is_valid_hex` | True if the payload is valid even-length hexadecimal. |
| `payload_is_missing` | True if the payload is missing or empty. |
| `payload_has_odd_nibble_count` | True if the payload has an odd number of hex nibbles. |
| `dlc` | Data Length Code, computed as payload hex length divided by 2. |
| `payload_exceeds_configured_length` | True when DLC exceeds `MAX_PAYLOAD_BYTES`. |

---

## 7. Compact feature extraction

The function `extract_can_features()` generates the compact set of features used by the simplified detector.

Unlike the earlier, more complex notebook, this version does not expand every byte, nibble, bit, or binary string. It keeps only the features that are actually consumed by the rules.

### 7.1 Timing and rate features

| Feature | Description | Computation |
|---|---|---|
| `delta_t_global_s` | Time since previous packet. | `timestamp_seconds.diff()` |
| `delta_t_same_id_s` | Time since previous packet with the same CAN ID. | Group by `arbitration_id`, then compute timestamp difference. |
| `packet_rate_last_time_window_hz` | Global packet rate in the recent time window. | Count packets in `[t - TIME_WINDOW_SECONDS, t]`, divided by `TIME_WINDOW_SECONDS`. |
| `same_id_rate_last_time_window_hz` | Per-ID packet rate in the recent time window. | Count packets with the same ID in `[t - TIME_WINDOW_SECONDS, t]`, divided by `TIME_WINDOW_SECONDS`. |
| `consecutive_id_streak_length` | Length of the current uninterrupted same-ID streak. | Increment count while consecutive packets have the same CAN ID. |
| `prev_arbitration_id` | Previous packet's CAN ID. | Shift parsed CAN ID by one row. |

These features mainly support detection of flooding, periodicity violations, and unexpected message sequences.

### 7.2 Rolling ID diversity features

| Feature | Description | Computation |
|---|---|---|
| `rolling_unique_id_count` | Number of different CAN IDs in a rolling packet window. | Count unique factorized CAN IDs over `ROLLING_PACKET_WINDOW`. |
| `rolling_id_entropy_bits` | Entropy of CAN ID distribution in the rolling packet window. | Shannon entropy over factorized CAN IDs. |

These features are useful for identifying fuzzy/random traffic, where many different CAN IDs may appear in a short sequence.

### 7.3 Payload features

Payload features are extracted from a fixed-width byte matrix derived from `payload_hex_normalized`.

Invalid payloads produce `NaN` values for payload-dependent features.

| Feature | Description | Computation |
|---|---|---|
| `payload_byte_sum` | Sum of payload byte values. | Convert payload hex to bytes and sum valid bytes. |
| `payload_byte_entropy_bits` | Entropy of byte values inside the payload. | Shannon entropy over payload bytes. |
| `payload_hamming_distance_prev_same_id` | Bit-level difference from previous same-ID payload. | XOR current payload bytes with previous same-ID payload bytes and count changed bits. |

These features support detection of payload profile deviations, malformed data, and replay-like repeated payloads with abnormal timing.

---

## 8. End-to-end feature wrapper

The function `extract_features_for_rule_detector()` combines three steps:

1. `standardize_raw_can_columns()`
2. `preprocess_can_dataframe()`
3. `extract_can_features()`

It returns:

```python
features_df, true_labels
```

- `features_df` contains all parsed fields and generated features.
- `true_labels` contains labels only if the input CSV had a configured label column.

This function is used both in training and evaluation, ensuring that training and evaluation files are processed consistently.

---

## 9. Detector class

The core detector is implemented in:

```python
CANRuleBasedDetector
```

It has three main responsibilities:

1. Learn benign thresholds using `fit()`.
2. Save and load detector profiles using `save()` and `load()`.
3. Apply explicit attack rules using `predict()`.

---

## 10. Training / calibration logic

Training uses benign-only feature data.

The detector does not learn attack signatures from attack samples. Instead, it learns normal behavior and flags deviations from that behavior.

### 10.1 Learned global thresholds

The detector calculates these global thresholds:

| Threshold | Based on feature | Meaning |
|---|---|---|
| `delta_t_global_low` | `delta_t_global_s` | Very small global inter-arrival time. |
| `packet_rate_high` | `packet_rate_last_time_window_hz` | Abnormally high global packet rate. |
| `same_id_rate_high` | `same_id_rate_last_time_window_hz` | Abnormally high per-ID packet rate. |
| `consecutive_id_streak_high` | `consecutive_id_streak_length` | Too many consecutive packets with the same ID. |
| `rolling_unique_id_count_high` | `rolling_unique_id_count` | Too many unique IDs in rolling window. |
| `rolling_id_entropy_high` | `rolling_id_entropy_bits` | Too much ID-distribution entropy. |
| `payload_entropy_high` | `payload_byte_entropy_bits` | Too much payload byte entropy. |
| `hamming_same_id_high` | `payload_hamming_distance_prev_same_id` | Too much bit-level payload change for same ID. |

Most high thresholds use `HIGH_QUANTILE`, default `0.995`. The lower inter-arrival threshold uses `LOW_QUANTILE`, default `0.005`.

### 10.2 Learned per-ID profiles

For each benign CAN ID, the detector learns:

| Profile item | Meaning |
|---|---|
| Allowed DLC values | Which DLC values were observed for this CAN ID. |
| Low same-ID delta time | Lower normal timing bound for this CAN ID. |
| High same-ID delta time | Upper normal timing bound for this CAN ID. |
| High same-ID rate | Upper normal rate for this CAN ID. |
| High hamming distance | Upper normal payload bit-change bound for this CAN ID. |
| Low payload byte sum | Lower normal payload-sum bound for this CAN ID. |
| High payload byte sum | Upper normal payload-sum bound for this CAN ID. |

This per-ID calibration is important because CAN IDs often have different message frequencies, DLCs, and payload patterns.

### 10.3 Learned ID transitions

The detector also learns pairs of consecutive CAN IDs observed in benign traffic:

```text
(previous_arbitration_id, current_arbitration_id)
```

During evaluation, a transition between two known IDs can be flagged if it was never observed in the benign training file.

---

## 11. Saved detector profile

After training, the detector is saved to JSON using:

```python
detector.save(profile_file, feature_config=feature_config)
```

The JSON profile includes:

| JSON field | Content |
|---|---|
| `metadata` | Creation timestamp and profile version. |
| `high_quantile` | High quantile used for calibration. |
| `low_quantile` | Low quantile used for calibration. |
| `min_attack_score` | Minimum score required to output an attack label. |
| `feature_config` | Saved feature settings such as payload length and time window. |
| `global_thresholds` | Global thresholds learned from benign traffic. |
| `allowed_ids` | CAN IDs observed in benign training data. |
| `allowed_dlc_by_id` | Allowed DLC values per benign CAN ID. |
| `allowed_transitions` | Consecutive CAN-ID transitions observed in benign traffic. |
| `id_thresholds` | Per-ID timing, rate, payload, and hamming thresholds. |

The profile allows future evaluation without recalculating thresholds.

---

## 12. Attack scoring and prediction

The detector applies rules in `CANRuleBasedDetector.predict()`.

The supported attack classes are:

```python
["DoS", "fuzzy", "spoofing", "replay"]
```

Each rule adds points to one attack class. After all rules are evaluated:

1. The detector finds the class with the highest score.
2. If the maximum score is below `MIN_ATTACK_SCORE`, the prediction becomes `normal`.
3. Otherwise, the prediction is the highest-scoring attack class.

Output columns include:

| Output column | Meaning |
|---|---|
| `predicted_label` | Final predicted class. |
| `max_rule_score` | Highest attack-class score for the packet. |
| `score_DoS` | Total DoS score. |
| `score_fuzzy` | Total fuzzy score. |
| `score_spoofing` | Total spoofing score. |
| `score_replay` | Total replay score. |
| `rule_*` columns | Binary indicators showing which rules fired. |

---

## 13. Rules used by the detector

The rules have a format like this:
```python
   self._add_rule(scores, flags, "DoS", "high_global_packet_rate",df["packet_rate_last_time_window_hz"] > gt.get("packet_rate_high", np.inf), 2.0
)
```
the structure is the following:

| Parameter                   | Meaning                                        |
| --------------------------- | ---------------------------------------------- |
| `scores`                    | Numerical anomaly score accumulator            |
| `flags`                     | Stores which rules triggered                   |
| `"DoS"`                     | Attack category                                |
| `"high_global_packet_rate"` | Name of the rule                               |
| `condition`                 | Boolean condition determining if rule triggers |
| `2.0`                       | Severity / score weight                        |

Pften the conditions have something like "gt.get("packet_rate_high", np.inf)" 
Get the threshold if it exists, otherwise use infinity which sets the codition false.

### 13.1 DoS / flooding rules

| Rule flag | Score | Condition | Intuition |
|---|---:|---|---|
| `rule_DoS_high_global_packet_rate` | 2.0 | `packet_rate_last_time_window_hz > packet_rate_high` | Too many packets globally. |
| `rule_DoS_very_small_global_delta_t` | 1.5 | `delta_t_global_s < delta_t_global_low` | Packets are arriving too close together. |
| `rule_DoS_same_id_rate_too_high` | 2.0 | Same-ID rate exceeds global or per-ID learned threshold. | One ID is appearing too frequently. |
| `rule_DoS_long_consecutive_id_streak` | 1.5 | `consecutive_id_streak_length > consecutive_id_streak_high` | Same ID repeats for too long. |

### 13.2 Fuzzy / malformed traffic rules

| Rule flag | Score | Condition | Intuition |
|---|---:|---|---|
| `rule_fuzzy_unknown_arbitration_id` | 3.0 | CAN ID not present in benign training IDs. | Unknown/random IDs are suspicious. |
| `rule_fuzzy_invalid_payload` | 3.0 | Payload is not valid even-length hex. | Malformed payload. |
| `rule_fuzzy_high_id_diversity` | 1.5 | Rolling unique ID count or ID entropy is above benign threshold. | Randomized/fuzzy traffic often increases ID diversity. |
| `rule_fuzzy_high_payload_entropy` | 1.0 | Payload byte entropy is above benign threshold. | Payload looks unusually random. |

### 13.3 Spoofing / profile-deviation rules

| Rule flag | Score | Condition | Intuition |
|---|---:|---|---|
| `rule_spoofing_dlc_unusual_for_known_id` | 2.0 | Known CAN ID uses a DLC not seen during benign training. | Same ID has abnormal payload length. |
| `rule_spoofing_same_id_timing_out_of_profile` | 2.0 | Same-ID timing is below or above the learned per-ID range. | Known ID appears at abnormal timing. |
| `rule_spoofing_payload_sum_out_of_profile` | 1.5 | Payload byte sum is outside the learned per-ID range. | Payload values differ from normal range for that ID. |
| `rule_spoofing_hamming_distance_out_of_profile` | 1.5 | Payload hamming distance exceeds per-ID or global threshold. | Payload changes too much compared with previous same-ID message. |
| `rule_spoofing_unexpected_id_transition` | 1.5 | Transition between two known IDs was not seen during training. | Message order differs from benign sequence. |

### 13.4 Replay-like rule

| Rule flag | Score | Condition | Intuition |
|---|---:|---|---|
| `rule_replay_repeated_payload_bad_timing` | 2.0 | Known ID, same payload as previous same-ID packet, and same-ID timing is abnormal. | Payload repeats exactly but at suspicious timing. |

---

## 14. Feature-to-rule mapping

| Feature | Main rules using it |
|---|---|
| `arbitration_id` | Unknown ID, known-ID DLC checks, per-ID timing/rate/payload thresholds, ID transitions. |
| `prev_arbitration_id` | Unexpected ID transition. |
| `dlc` | DLC unusual for known ID. |
| `payload_is_valid_hex` | Invalid payload. |
| `delta_t_global_s` | Very small global delta time. |
| `delta_t_same_id_s` | Same-ID timing out of profile, replay repeated payload bad timing. |
| `packet_rate_last_time_window_hz` | High global packet rate. |
| `same_id_rate_last_time_window_hz` | Same-ID rate too high. |
| `consecutive_id_streak_length` | Long consecutive ID streak. |
| `rolling_unique_id_count` | High ID diversity. |
| `rolling_id_entropy_bits` | High ID diversity. |
| `payload_byte_sum` | Payload sum out of profile. |
| `payload_byte_entropy_bits` | High payload entropy. |
| `payload_hamming_distance_prev_same_id` | Hamming distance out of profile, replay repeated payload bad timing. |

---

## 15. Training pipeline

The training function is:

```python
train_detector_and_save_profile(
    train_file,
    profile_file,
    config,
    max_payload_bytes=8,
    rolling_packet_window=100,
    time_window_seconds=1.0,
    high_quantile=0.995,
    low_quantile=0.005,
    min_attack_score=2.0,
)
```

It performs these steps:

1. Loads the benign training CSV using `load_can_csv()`.
2. Extracts features using `extract_features_for_rule_detector()`.
3. Creates a `CANRuleBasedDetector`.
4. Fits the detector on benign features using `fit()`.
5. Saves the detector profile to JSON.
6. Prints a summary of thresholds, known IDs, transitions, and feature settings.
7. Returns the detector and training features dataframe.

The training stage cell runs this function only when:

```python
RUN_TRAINING_STAGE = True
```

After the profile is created, the user should set it back to `False`.

---

## 16. Evaluation pipeline

The evaluation stage normally uses:

```python
evaluate_files_from_saved_profile(
    EVALUATION_FILES,
    DETECTOR_PROFILE_FILE,
    config,
    evaluation_mode=EVALUATION_MODE,
)
```

This function:

1. Checks whether the detector profile JSON exists.
2. Loads the profile with `CANRuleBasedDetector.load()`.
3. Prints the detector summary.
4. Calls `evaluate_files()`.

For each evaluation file, `evaluate_files()`:

1. Loads the CSV.
2. Extracts features using the feature settings saved in the detector profile.
3. Applies `detector.predict()`.
4. Adds a `source_file` column.
5. Computes metrics if true labels are available.
6. Prints prediction distribution, average rule scores, top triggered rules, and most suspicious rows.
7. Returns the predictions dataframe.

If multiple evaluation files are provided, the function concatenates their results and prints combined results.

---

## 17. Evaluation metrics

The notebook supports two evaluation modes:

```python
EVALUATION_MODE = "binary"
```

or:

```python
EVALUATION_MODE = "multiclass"
```

### Binary mode

Binary mode maps labels to:

```text
normal
attack
```

Values such as `0`, `normal`, `benign`, `false`, `none`, and `no_attack` are treated as normal. Everything else is treated as attack.

Predicted labels are also mapped to binary:

- `normal` remains `normal`.
- `DoS`, `fuzzy`, `spoofing`, and `replay` become `attack`.

### Multiclass mode

Multiclass mode maps labels to simplified attack families:

| Label content | Normalized class |
|---|---|
| `dos`, `flood`, `frequency` | `DoS` |
| `fuzz`, `random`, `malformed` | `fuzzy` |
| `replay` | `replay` |
| `spoof`, `imperson`, `masquerade`, `payload`, `dlc`, `timing` | `spoofing` |
| Normal keywords | `normal` |

The notebook computes:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix
- Classification report

---

## 18. Typical usage workflow

### Step 1: Configure paths and columns

Edit the user configuration cell:

```python
TRAINING_FILE = "benign_training_dataset.csv"
DETECTOR_PROFILE_FILE = "can_detector_profile.json"
EVALUATION_FILES = ["evaluation_dataset_with_attacks.csv"]
TIMESTAMP_COL = "timestamp"
ARBITRATION_ID_COL = "arbitration_id"
DATA_FIELD_COL = "data_field"
LABEL_COL = "attack"
```

### Step 2: Train once

Set:

```python
RUN_TRAINING_STAGE = True
RUN_EVALUATION_STAGE = False
```

Run the notebook through the training stage. This creates or updates `can_detector_profile.json`.

### Step 3: Evaluate repeatedly

Set:

```python
RUN_TRAINING_STAGE = False
RUN_EVALUATION_STAGE = True
```

Change only:

```python
EVALUATION_FILES = ["new_evaluation_file.csv"]
```

Then rerun the evaluation stage. The detector loads the saved profile and does not retrain.

---

## 19. Why the split training/evaluation design matters

The saved-profile design has several advantages:

1. **Efficiency**
   - Thresholds are calculated once instead of every evaluation run.

2. **Consistency**
   - Evaluation uses exactly the thresholds and feature settings learned during training.

3. **Reproducibility**
   - The JSON profile records calibration settings, thresholds, known IDs, allowed DLCs, transitions, and per-ID profiles.

4. **Operational realism**
   - In a real IDS scenario, the detector profile would be trained on trusted benign data and then deployed to monitor future traffic.

---

## 20. Important assumptions

The notebook assumes:

1. The training file contains only benign traffic.
2. The benign training file is representative of normal vehicle/network behavior.
3. CAN IDs, DLC values, timing, payload sums, and transitions are relatively stable under normal conditions.
4. The evaluation files use the same timestamp units and schema mapping as training.
5. Evaluation feature settings match training feature settings. This is enforced by saving feature settings in the profile.

---

## 21. Limitations

This detector is intentionally simple and interpretable. It is not a machine-learning classifier.

Main limitations:

1. **Dependence on benign training quality**
   - If normal behavior is missing from the benign training file, the detector may flag valid traffic as anomalous.

2. **Static thresholds**
   - Thresholds are fixed after training. They do not adapt online unless the profile is retrained.

3. **Limited payload modeling**
   - Payload behavior is summarized using byte sum, entropy, and hamming distance. The detector does not model full signal semantics.

4. **Transition sensitivity**
   - Unexpected ID transitions may be noisy if the training file does not include all normal driving states.

5. **Attack family approximation**
   - Rule labels such as `DoS`, `fuzzy`, `spoofing`, and `replay` are heuristic categories. A real attack may trigger multiple categories.

6. **Timestamp assumptions**
   - Rate and timing features assume meaningful numeric timestamps. If timestamps are missing, unsorted, or use inconsistent units, timing rules become less reliable.

---

## 22. Interpreting results

When reviewing output, focus on:

1. `predicted_label`
   - The final label assigned by the detector.

2. `max_rule_score`
   - Higher scores indicate stronger rule-based evidence.

3. `score_DoS`, `score_fuzzy`, `score_spoofing`, `score_replay`
   - These show which attack family received the strongest support.

4. `rule_*` columns
   - These are the most important explanation fields because they show exactly why a packet was flagged.

5. Top suspicious rows
   - The notebook sorts packets by `max_rule_score` to show the most suspicious packets first.

A packet can trigger multiple rules. The final class is the class with the highest total score, unless the score is below `MIN_ATTACK_SCORE`.

---

## 23. Practical tuning guidance

The most important parameters to tune are:

| Parameter | Effect of increasing it | Effect of decreasing it |
|---|---|---|
| `HIGH_QUANTILE` | More tolerant upper thresholds, fewer false positives, possible missed attacks. | Stricter upper thresholds, more detections, possible false positives. |
| `LOW_QUANTILE` | Higher lower threshold if increased, stricter for small timing gaps. | Lower lower threshold, more tolerant of small timing gaps. |
| `MIN_ATTACK_SCORE` | Requires stronger evidence to flag attacks. | Flags packets with weaker evidence. |
| `TIME_WINDOW_SECONDS` | Smoother rate estimates over longer windows. | More reactive rate estimates over shorter windows. |
| `ROLLING_PACKET_WINDOW` | Smoother ID diversity/entropy estimates. | More reactive ID diversity/entropy estimates. |

For an academic or prototype setting, the current defaults are a reasonable interpretable starting point. For a real deployment, thresholds should be validated on multiple benign driving scenarios.

---

## 24. Summary

The notebook implements a compact, interpretable CAN intrusion detector with a clean separation between training and evaluation.

The training stage learns a benign profile consisting of:

- Known CAN IDs
- Allowed DLCs per ID
- Global timing/rate/diversity/payload thresholds
- Per-ID timing/rate/payload thresholds
- Allowed CAN-ID transitions
- Feature extraction settings

The evaluation stage reuses this saved profile and applies explicit rules for:

- DoS / flooding behavior
- Fuzzy or malformed traffic
- Spoofing or profile deviation
- Replay-like repeated payloads with abnormal timing

The result is a simpler detector than the original version, with fewer features, fewer rules, and a clearer explanation path for every prediction.
