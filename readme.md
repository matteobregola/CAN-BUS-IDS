# CAN Rule-Based IDS Documentation

## 1. High-Level Architecture

The function is organized into the following sections:

| Notebook section            | Main responsibility                                                                        |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| User Configuration          | Defines file paths, column names, feature settings, calibration settings, and rule scores. |
| Constants and Configuration | Defines CAN limits, column configuration, print settings, and core feature names.          |
| Preprocessing               | Parses timestamps, CAN IDs, payloads, DLC values, and diagnostic flags.                    |
| Compact Feature Extraction  | Computes the feature set used by the detector rules.                                       |
| End-to-End Feature Wrapper  | Combines standardization, preprocessing, and feature extraction.                           |
| Rule-Based Detector         | Learns benign profiles, saves/loads profiles, and applies detection rules.                 |
| Training Stage              | Creates or updates the saved detector profile.                                             |

---

## 2. User Configuration

The main configuration cell contains the values normally edited by the user.

### 2.1 File Paths

```python

DETECTOR_PROFILE_FILE = "can_detector_profile.json"

```

| Variable                | Meaning                                                |
| ----------------------- | ------------------------------------------------------ |
| `DETECTOR_PROFILE_FILE` | JSON file where the trained detector profile is saved. |


---

### 2.2 Execution Flags

```python
RUN_TRAINING_STAGE = False
```

| Variable             | Meaning                                                                         |
| -------------------- | ------------------------------------------------------------------------------- |
| `RUN_TRAINING_STAGE` | When `True`, the notebook trains/calibrates the detector and saves the profile. |

Typical workflow:

1. Set `RUN_TRAINING_STAGE = True` once to create the profile.
2. Set `RUN_TRAINING_STAGE = False`.

---

### 2.3 Feature Extraction Settings

```python
MAX_PAYLOAD_BYTES = 8
ROLLING_PACKET_WINDOW = 100
TIME_WINDOW_SECONDS = 1.0
```

| Variable                | Meaning                                                                          |
| ----------------------- | -------------------------------------------------------------------------------- |
| `MAX_PAYLOAD_BYTES`     | Maximum number of payload bytes considered. Default `8`, matching classical CAN. |
| `ROLLING_PACKET_WINDOW` | Rolling packet window used for ID diversity and entropy features.                |
| `TIME_WINDOW_SECONDS`   | Time window used for global and per-ID packet-rate features.                     |

These settings are saved into the detector profile during training and reused during evaluation.

---

### 2.4 Calibration Settings

```python
HIGH_QUANTILE = 0.995
LOW_QUANTILE = 0.005
MIN_ATTACK_SCORE = 0.5
```

| Variable           | Meaning                                                            |
| ------------------ | ------------------------------------------------------------------ |
| `HIGH_QUANTILE`    | Upper quantile used to learn high-end benign thresholds.           |
| `LOW_QUANTILE`     | Lower quantile used to learn low-end benign thresholds.            |
| `MIN_ATTACK_SCORE` | Minimum score required for a packet to be classified as an attack. |

In the current notebook, `MIN_ATTACK_SCORE = 0.5`. This means a packet is classified as malicious if the strongest attack-class score is at least `0.5`.

---

### 2.5 Rule Score Weights

Our idea was to create rules of what we have seen in calss and assign how strong that rule is an indicator for that specific attack. If is greater or equal to 50% DDOS then it flagged as an attack. The rules for each class are additive in the sense that all rules of DDOS which are applied are summed.

```python
LOW = 0.125
MEDIUM = 0.25
HIGH = 0.375
TRIGGER = 0.5
PRIORITY = 1.0
```

| Score constant |   Value | Meaning                                                                              |
| -------------- | ------: | ------------------------------------------------------------------------------------ |
| `LOW`          | `0.125` | Weak evidence. Usually needs to combine with other rules.                            |
| `MEDIUM`       |  `0.25` | Moderate evidence.                                                                   |
| `HIGH`         | `0.375` | Strong evidence, but still below the default attack threshold alone.                 |
| `TRIGGER`      |   `0.5` | Sufficient by itself to trigger an attack label.                                     |
| `PRIORITY`     |   `1.0` | Strong priority evidence, used when a rule should dominate weaker overlapping rules. |

The score constants are code-level settings. They are not saved inside the JSON detector profile.

---


## 3. CSV Loading and Column Standardization

### 3.1 `_build_data_field_from_byte_columns()`

This helper builds a single hexadecimal payload string from separate byte columns.

Example input:

```text
byte_0, byte_1, byte_2
1, 10, 255
```

Output:

```text
010AFF
```

The function:

- Accepts decimal byte values.
- Accepts hexadecimal-looking byte values such as `0x0A`.
- Skips invalid or missing byte values.
- Keeps only bytes in the range `0` to `255`.

---

### 3.2 `standardize_raw_can_columns()`

```python
standardize_raw_can_columns(raw_df, config)
```

This function maps dataset-specific columns into the notebook's canonical schema.

It performs the following steps:

1. Checks that the timestamp and arbitration ID columns exist.
2. Copies the configured timestamp column to `timestamp`.
3. Copies the configured arbitration ID column to `arbitration_id`.
4. Copies the configured label column to `__true_label` if present.
5. Adds a temporary `attack` column with value `0`.

---

## 4. Preprocessing

The main preprocessing function is:

```python
preprocess_can_dataframe(raw_df, max_payload_bytes=CAN_CLASSIC_MAX_BYTES)
```

It converts raw CAN packets into parsed, cleaned, rule-ready columns.

---

### 4.1 Timestamp Parsing

The notebook creates the following timestamp-related columns:

| Column                  | Meaning                                          |
| ----------------------- | ------------------------------------------------ |
| `timestamp_raw`         | Original timestamp value.                        |
| `timestamp_seconds`     | Numeric timestamp parsed with `pd.to_numeric()`. |
| `timestamp_parse_valid` | `True` if timestamp parsing succeeded.           |
| `time_from_start_s`     | Time difference from the first valid timestamp.  |

The dataframe is sorted by `timestamp_seconds` using stable chronological sorting:

```python
df.sort_values("timestamp_seconds", kind="mergesort", na_position="last")
```

This means:

- Packets are processed in timestamp order.
- Rows with equal timestamps keep their original relative order.
- Rows with invalid timestamps are placed at the end.

---

### 4.2 Arbitration ID Parsing

The helper function `_parse_can_identifier()` parses CAN IDs.

| Input form               | Interpretation                                 |
| ------------------------ | ---------------------------------------------- |
| `0x123`                  | Hexadecimal.                                   |
| `1AB`                    | Hexadecimal because it contains letters `A-F`. |
| `123`                    | Decimal because it contains only digits.       |
| Invalid value            | Converted to `NaN`.                            |
| Negative value           | Converted to `NaN`.                            |
| Value above `0x1FFFFFFF` | Converted to `NaN`.                            |

Generated columns:

| Column                       | Meaning                                    |
| ---------------------------- | ------------------------------------------ |
| `arbitration_id_raw`         | Original arbitration ID value.             |
| `arbitration_id`             | Parsed numeric CAN ID as a float.          |
| `arbitration_id_parse_valid` | Whether parsing succeeded.                 |
| `arbitration_id_hex`         | Human-readable hexadecimal representation. |

Assumption: decimal-looking strings such as `"123"` are interpreted as decimal, not hexadecimal. If a dataset stores hexadecimal IDs without `0x` and without letters `A-F`, the column mapping or parsing logic may need to be adjusted.

---

### 4.3 Payload Normalization

The helper function `_normalize_payload_hex()` normalizes the raw payload.

It performs the following operations:

1. Converts the value to uppercase text.
2. Removes a leading `0x`.
3. Removes common separators:
   - spaces
   - hyphens
   - colons
   - underscores
   - commas
4. Checks whether the remaining text contains only hexadecimal characters.
5. Checks whether the number of hexadecimal nibbles is even.

Generated columns:

| Column                              | Meaning                                                            |
| ----------------------------------- | ------------------------------------------------------------------ |
| `data_field_raw`                    | Original raw payload value.                                        |
| `payload_hex_normalized`            | Clean uppercase hexadecimal payload string.                        |
| `payload_is_valid_hex`              | `True` if the payload is valid even-length hexadecimal.            |
| `payload_is_missing`                | `True` if the payload is missing or empty.                         |
| `payload_has_odd_nibble_count`      | `True` if the payload has an odd number of hex nibbles.            |
| `dlc`                               | Data Length Code, computed as valid payload length divided by two. |
| `payload_exceeds_configured_length` | `True` if `dlc > MAX_PAYLOAD_BYTES`.                               |

Invalid payloads receive `NaN` for DLC and payload-derived numerical features.

---

## 5. Compact Feature Extraction

The main feature extraction function is:

```python
extract_can_features(
    preprocessed_df,
    rolling_packet_window=100,
    time_window_seconds=1.0,
    max_payload_bytes=8,
    print_summary=True,
)
```

The function returns:

```python
features_df, generated_features
```

The current implementation generates timing, rate, rolling ID-diversity, payload, hamming-distance, and structural byte-standard-deviation features.

---

### 5.1 Timing and Rate Features

| Feature                            | Description                                          | Computation                                                                                         |
| ---------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `delta_t_global_s`                 | Time since the previous packet.                      | Difference between consecutive `timestamp_seconds` values.                                          |
| `delta_t_same_id_s`                | Time since the previous packet with the same CAN ID. | Group by `arbitration_id`, then compute timestamp difference.                                       |
| `packet_rate_last_time_window_hz`  | Global packet rate in the recent time window.        | Count packets in `[t - TIME_WINDOW_SECONDS, t]`, divided by `TIME_WINDOW_SECONDS`.                  |
| `same_id_rate_last_time_window_hz` | Per-ID packet rate in the recent time window.        | Count packets with the same ID in `[t - TIME_WINDOW_SECONDS, t]`, divided by `TIME_WINDOW_SECONDS`. |
| `consecutive_id_streak_length`     | Length of the current uninterrupted same-ID streak.  | Counts consecutive packets with the same arbitration ID.                                            |
| `prev_arbitration_id`              | Previous packet's arbitration ID.                    | Shifted `arbitration_id` column.                                                                    |

The rate features include the current packet in the time-window count.

---

### 5.2 Rolling ID-Diversity Features

| Feature                   | Description                                                          | Computation                                   |
| ------------------------- | -------------------------------------------------------------------- | --------------------------------------------- |
| `rolling_unique_id_count` | Number of distinct CAN IDs in the recent rolling packet window.      | Rolling unique count over factorized CAN IDs. |
| `rolling_id_entropy_bits` | Shannon entropy of CAN ID distribution in the rolling packet window. | Rolling entropy over factorized CAN IDs.      |

These features are mainly used to detect fuzzy or randomized traffic, where ID diversity or ID entropy increases abnormally.

---

### 5.3 Payload Features

Payload features are computed from a fixed-width byte matrix derived from `payload_hex_normalized`.

| Feature                                 | Description                                             | Computation                                                           |
| --------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------- |
| `payload_byte_sum`                      | Sum of payload byte values.                             | Convert valid payload hex to bytes and sum valid byte values.         |
| `payload_byte_entropy_bits`             | Entropy of byte values inside the payload.              | Shannon entropy over the payload bytes.                               |
| `payload_hamming_distance_prev_same_id` | Bit-level difference from the previous same-ID payload. | XOR current bytes with previous same-ID bytes and count changed bits. |

The hamming-distance feature compares only byte positions that are valid in both the current and previous same-ID payload. If no comparable previous same-ID payload exists, the value is `NaN`.

---

### 5.4 Structural Byte-Standard-Deviation Features

The current notebook adds two structural payload features:

| Feature                  | Description                                            | Computation                                                   |
| ------------------------ | ------------------------------------------------------ | ------------------------------------------------------------- |
| `payload_odd_bytes_std`  | Standard deviation of bytes at positions `1, 3, 5, 7`. | Population standard deviation over valid odd-position bytes.  |
| `payload_even_bytes_std` | Standard deviation of bytes at positions `0, 2, 4, 6`. | Population standard deviation over valid even-position bytes. |

These features are used to detect fuzzy injection on known IDs when timing still looks normal.

The feature extraction function computes these values independently for odd and even byte positions. A row must have at least two valid bytes in the selected positions; otherwise, the feature value is `NaN`.

Assumption: the structural byte-standard-deviation code assumes payload matrices have positions up to byte index `7`. With the default `MAX_PAYLOAD_BYTES = 8`, this is valid. Although the preprocessing validation allows smaller payload limits, the current structural feature code is written for the default 8-byte configuration.

---

### 5.5 Generated Feature Set

The current generated feature set is:

| Feature                                 |
| --------------------------------------- |
| `delta_t_global_s`                      |
| `delta_t_same_id_s`                     |
| `packet_rate_last_time_window_hz`       |
| `same_id_rate_last_time_window_hz`      |
| `consecutive_id_streak_length`          |
| `prev_arbitration_id`                   |
| `rolling_unique_id_count`               |
| `rolling_id_entropy_bits`               |
| `payload_byte_sum`                      |
| `payload_byte_entropy_bits`             |
| `payload_hamming_distance_prev_same_id` |
| `payload_odd_bytes_std`                 |
| `payload_even_bytes_std`                |

The notebook still defines `CORE_FEATURE_COLUMNS` with the original 11 core features, but the actual feature extraction function now generates 13 features, including the two structural byte-standard-deviation features. Therefore, `payload_odd_bytes_std` and `payload_even_bytes_std` are generated by the current feature extractor, even though they are not part of the historical core feature list.

---

## 6. End-to-End Feature Wrapper

The function:

```python
extract_features_for_rule_detector(
    raw_df,
    config,
    max_payload_bytes=8,
    rolling_packet_window=100,
    time_window_seconds=1.0,
    print_summary=False,
)
```

runs the complete feature pipeline:

1. `standardize_raw_can_columns()`
2. `preprocess_can_dataframe()`
3. `extract_can_features()`

It returns:

```python
features_df, true_labels
```

| Return value  | Meaning                                                              |
| ------------- | -------------------------------------------------------------------- |
| `features_df` | Parsed packet fields and generated features.                         |
| `true_labels` | Optional labels copied from the input CSV, if a label column exists. |

If labels are present, they are removed from `features_df` before detection and returned separately. This prevents labels from influencing prediction.

---

## 7. Detector Class

The detector is implemented in:

```python
CANRuleBasedDetector
```

Its profile version is:

```python
profile_version = "Detector-Potentissimo-V1"
```

The detector has three main responsibilities:

1. **Fit**
   - Learn benign thresholds from training features.

2. **Save / load**
   - Store and reload a JSON profile containing thresholds and learned benign behavior.

3. **Predict**
   - Apply explicit rules to evaluation traffic and produce labels, scores, and rule flags.

The detector supports five attack classes:

```python
["DoS", "fuzzy", "spoofing", "masquerade", "replay"]
```

---

## 8. Training / Calibration Logic

Training uses only benign traffic.

The function:

```python
detector.fit(benign_features_df)
```

learns global thresholds, per-ID profiles, payload reuse profiles, structural byte profiles, and allowed ID transitions.

---

### 8.1 Required Training Features

The detector requires the following columns during fitting:

| Required feature                        |
| --------------------------------------- |
| `arbitration_id`                        |
| `dlc`                                   |
| `delta_t_global_s`                      |
| `delta_t_same_id_s`                     |
| `packet_rate_last_time_window_hz`       |
| `same_id_rate_last_time_window_hz`      |
| `consecutive_id_streak_length`          |
| `prev_arbitration_id`                   |
| `rolling_unique_id_count`               |
| `rolling_id_entropy_bits`               |
| `payload_byte_sum`                      |
| `payload_byte_entropy_bits`             |
| `payload_hamming_distance_prev_same_id` |

The structural features `payload_odd_bytes_std` and `payload_even_bytes_std` are generated by the current feature extractor, but they are optional for the detector fitting procedure. This means they are not included in the required feature-column check used by `fit()`. If the columns are present, the detector learns per-ID structural byte-stability thresholds and can later enable the structural incoherence fuzzy rule. If the columns are absent, the detector skips this structural profiling step and still fits using the core feature set.

---

### 8.2 Learned Global Thresholds

The detector learns these global thresholds:

| Threshold                      | Based on feature                        | Meaning                                            |
| ------------------------------ | --------------------------------------- | -------------------------------------------------- |
| `delta_t_global_low`           | `delta_t_global_s`                      | Very small global inter-arrival time.              |
| `packet_rate_high`             | `packet_rate_last_time_window_hz`       | Abnormally high global packet rate.                |
| `same_id_rate_high`            | `same_id_rate_last_time_window_hz`      | Abnormally high per-ID packet rate.                |
| `consecutive_id_streak_high`   | `consecutive_id_streak_length`          | Too many consecutive packets with the same ID.     |
| `rolling_unique_id_count_high` | `rolling_unique_id_count`               | Too many unique IDs in the rolling window.         |
| `rolling_id_entropy_high`      | `rolling_id_entropy_bits`               | Too much rolling ID-distribution entropy.          |
| `payload_entropy_high`         | `payload_byte_entropy_bits`             | Too much payload byte entropy.                     |
| `hamming_same_id_high`         | `payload_hamming_distance_prev_same_id` | Too much bit-level payload change for the same ID. |

Most high thresholds use `HIGH_QUANTILE`, which defaults to `0.995`.

The low global inter-arrival threshold uses `LOW_QUANTILE`, which defaults to `0.005`.

For `consecutive_id_streak_high`, the detector enforces a minimum threshold of `5.0`.

---

### 8.3 Learned Per-ID Profiles

For each CAN ID observed in benign training traffic, the detector learns:

| Per-ID profile item      | Meaning                                                 |
| ------------------------ | ------------------------------------------------------- |
| Allowed DLC values       | DLC values observed for that ID during benign training. |
| `delta_t_low`            | Low quantile of same-ID inter-arrival time.             |
| `delta_t_high`           | High quantile of same-ID inter-arrival time.            |
| `delta_t_median`         | Median same-ID inter-arrival time.                      |
| `same_id_rate_high`      | High quantile of same-ID packet rate.                   |
| `same_id_rate_median`    | Median same-ID packet rate.                             |
| `hamming_high`           | High quantile of same-ID payload hamming distance.      |
| `hamming_median`         | Median same-ID payload hamming distance.                |
| `payload_sum_low`        | Low quantile of payload byte sum.                       |
| `payload_sum_high`       | High quantile of payload byte sum.                      |
| `payload_reuse_gap_high` | High quantile of exact-payload reuse gap.               |
| `observation_count`      | Number of benign training rows for that ID.             |

This per-ID modeling is important because different CAN IDs can have different periods, DLC values, payload ranges, and update behavior.

---

### 8.4 Exact-Payload Reuse Gap Profile

The detector computes an internal training feature:

```python
__payload_reuse_gap_same_id_s
```

This value measures the time since the same CAN ID last used the exact same normalized payload.

For each CAN ID, the detector saves:

```python
payload_reuse_gap_high
```

This is the `payload_reuse_gap_quantile` of benign exact-payload reuse gaps. The default quantile is:

```python
payload_reuse_gap_quantile = 0.90
```

This profile supports the masquerade rule. Instead of using a fixed multiplier such as "20 times the median period", the current implementation derives stale-payload thresholds from benign training traffic.

---

### 8.5 Structural Byte-Stability Profiles

For DLC-8 packets, the detector can learn per-ID structural stability thresholds for odd and even payload byte lanes.

The learned dictionaries are:

```python
id_odd_bytes_std_high
id_even_bytes_std_high
```

Training logic:

1. Consider only rows with `dlc == 8`.
2. Compute the high quantile of `payload_odd_bytes_std` and `payload_even_bytes_std`.
3. Store the threshold only if:
   - at least two DLC-8 rows exist for that ID, and
   - the learned high-quantile threshold is finite, and
   - the threshold is less than or equal to `1.0`.

This means the structural incoherence rule applies only to IDs whose benign traffic shows very stable odd or even byte lanes.

---

### 8.6 Masquerade Applicability Thresholds

The current detector derives masquerade applicability thresholds from the distribution of benign CAN-ID profiles.

| Threshold                          | Derived from                        | Default quantile |
| ---------------------------------- | ----------------------------------- | ---------------: |
| `frequent_id_count_threshold`      | Per-ID observation counts.          |           `0.50` |
| `periodic_id_delta_threshold`      | Median same-ID inter-arrival times. |           `0.25` |
| `static_payload_hamming_threshold` | Median same-ID hamming distances.   |           `0.25` |

The corresponding constructor settings are:

```python
payload_reuse_gap_quantile = 0.90
fast_periodic_id_quantile = 0.25
static_payload_id_quantile = 0.25
frequent_id_support_quantile = 0.50
```

The intended interpretation is:

- A masquerade candidate should be a frequent benign ID.
- It should be relatively fast-periodic compared with other benign IDs.
- It should have relatively stable payload behavior.
- It should reuse an exact payload after a longer-than-normal benign reuse gap.

---

### 8.7 Allowed ID Transitions

The detector learns all observed benign transitions:

```text
(previous_arbitration_id, current_arbitration_id)
```

During evaluation, a transition between two known IDs can be flagged if it was not observed in benign training traffic.

Transitions involving unknown or missing IDs are not treated as unexpected transitions by this specific rule.

---

## 9. Saved Detector Profile

The detector is saved with:

```python
detector.save(profile_file, feature_config=feature_config)
```

The JSON profile contains:

| JSON field                      | Content                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------- |
| `metadata`                      | Creation timestamp and profile version.                                         |
| `high_quantile`                 | High quantile used during calibration.                                          |
| `low_quantile`                  | Low quantile used during calibration.                                           |
| `min_attack_score`              | Minimum score required to output an attack label.                               |
| `feature_config`                | Saved feature settings such as payload length, rolling window, and time window. |
| `global_thresholds`             | Global thresholds learned from benign traffic.                                  |
| `masquerade_profile_settings`   | Quantile settings used for masquerade profile calibration.                      |
| `masquerade_profile_thresholds` | Training-derived masquerade applicability thresholds.                           |
| `allowed_ids`                   | CAN IDs observed in benign training data.                                       |
| `allowed_dlc_by_id`             | Allowed DLC values per known CAN ID.                                            |
| `allowed_transitions`           | Consecutive CAN-ID transitions observed during benign training.                 |
| `id_thresholds`                 | Per-ID timing, rate, payload, hamming, reuse-gap, and support thresholds.       |
| `id_odd_bytes_std_high`         | Per-ID odd-byte structural stability thresholds.                                |
| `id_even_bytes_std_high`        | Per-ID even-byte structural stability thresholds.                               |

The profile allows evaluation to be repeated without recalculating thresholds.

---

## 10. Loading a Detector Profile

The detector is loaded with:

```python
CANRuleBasedDetector.load(profile_file)
```

Loading restores:

- global thresholds
- allowed CAN IDs
- allowed DLC values
- allowed ID transitions
- per-ID thresholds
- masquerade profile settings
- masquerade applicability thresholds
- structural byte-standard-deviation thresholds
- feature extraction settings

---

## 11. Prediction and Scoring

Prediction process:

1. Initialize all attack-class scores to `0.0`.
2. Evaluate each rule.
3. Add the rule's score to the corresponding attack class when the rule condition is true.
4. Select the attack class with the highest score.
5. If the highest score is below `MIN_ATTACK_SCORE`, output `normal`.
6. Otherwise, output the highest-scoring attack class.

With the current default `MIN_ATTACK_SCORE = 0.5`, any single `TRIGGER` rule is sufficient to classify a packet as malicious.

---

## 12. Rule Format

Rules are added using:

```python
self._add_rule(scores, flags, attack_type, rule_name, condition, points)
```

| Argument      | Meaning                                                       |
| ------------- | ------------------------------------------------------------- |
| `scores`      | Dataframe accumulating numerical scores by attack class.      |
| `flags`       | Dataframe storing binary rule activations.                    |
| `attack_type` | Attack class receiving the score.                             |
| `rule_name`   | Rule identifier used in the output column name.               |
| `condition`   | Boolean condition determining which packets trigger the rule. |
| `points`      | Score added when the rule triggers.                           |

The resulting rule flag column is named:

```text
rule_<attack_type>_<rule_name>
```

---

## 13. DoS / Flooding Rules

| Rule flag                             |              Score | Condition                                                   | Intuition                                                                   |
| ------------------------------------- | -----------------: | ----------------------------------------------------------- | --------------------------------------------------------------------------- |
| `rule_DoS_high_global_packet_rate`    |    `LOW` / `0.125` | `packet_rate_last_time_window_hz > packet_rate_high`        | Global packet rate is higher than benign traffic.                           |
| `rule_DoS_very_small_global_delta_t`  |    `LOW` / `0.125` | `delta_t_global_s < delta_t_global_low`                     | Packets are arriving too close together globally.                           |
| `rule_DoS_same_id_rate_too_high`      |    `LOW` / `0.125` | Same-ID rate exceeds the global or per-ID high threshold.   | A CAN ID is appearing too frequently.                                       |
| `rule_DoS_long_consecutive_id_streak` |    `LOW` / `0.125` | `consecutive_id_streak_length > consecutive_id_streak_high` | Same ID repeats for an unusually long streak.                               |
| `rule_DoS_zeros`                      | `PRIORITY` / `1.0` | `arbitration_id == 0` and `payload_byte_sum == 0`           | All-zero CAN ID and all-zero payload are treated as a strong DoS indicator. |

The `zeros` rule can overlap with fuzzy unknown-ID behavior, but it receives a priority score so that the packet is classified as DoS when this strong condition is met.

---

## 14. Fuzzy / Malformed Traffic Rules

| Rule flag                                 |             Score | Condition                                                                                         | Intuition                                                        |
| ----------------------------------------- | ----------------: | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `rule_fuzzy_unknown_arbitration_id`       | `TRIGGER` / `0.5` | CAN ID not seen in benign training.                                                               | Random or injected IDs are suspicious.                           |
| `rule_fuzzy_invalid_payload`              | `TRIGGER` / `0.5` | Payload is not valid even-length hexadecimal.                                                     | Malformed payload format.                                        |
| `rule_fuzzy_high_id_diversity`            |  `HIGH` / `0.375` | Rolling unique ID count or rolling ID entropy exceeds benign threshold.                           | Fuzzy traffic may increase ID diversity.                         |
| `rule_fuzzy_high_payload_entropy`         | `MEDIUM` / `0.25` | Payload byte entropy exceeds benign threshold.                                                    | Payload appears unusually random.                                |
| `rule_fuzzy_bytes_structural_incoherence` | `TRIGGER` / `0.5` | Odd or even byte-lane standard deviation exceeds the learned stable profile for a known DLC-8 ID. | Known-ID payload structure is inconsistent with benign behavior. |

The detector also creates two explanatory per-lane flags when structural profiles are available:

| Explanatory flag                               | Meaning                                                               |
| ---------------------------------------------- | --------------------------------------------------------------------- |
| `rule_fuzzy_odd_bytes_structural_incoherence`  | Odd byte positions `1, 3, 5, 7` exceed the learned per-ID threshold.  |
| `rule_fuzzy_even_bytes_structural_incoherence` | Even byte positions `0, 2, 4, 6` exceed the learned per-ID threshold. |

The per-lane flags are diagnostic. The scored rule is the combined OR condition:

```python
bytes_std_out = odd_bytes_std_out | even_bytes_std_out
```

---

## 15. Spoofing / Known-ID Profile-Deviation Rules

Spoofing is treated as behavior where a known CAN ID violates its benign profile.

| Rule flag                                             |             Score | Condition                                                             | Intuition                                                        |
| ----------------------------------------------------- | ----------------: | --------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `rule_spoofing_known_id_unusual_dlc`                  | `TRIGGER` / `0.5` | Known CAN ID uses a DLC not observed during benign training.          | Same ID appears with an abnormal payload length.                 |
| `rule_spoofing_known_id_unexpected_transition`        | `MEDIUM` / `0.25` | Transition between two known IDs was not seen during benign training. | Message ordering differs from benign behavior.                   |
| `rule_spoofing_known_id_timing_outside_profile`       |   `LOW` / `0.125` | Same-ID timing is below or above the learned per-ID range.            | Known ID appears at abnormal timing.                             |
| `rule_spoofing_known_id_payload_sum_outside_profile`  |   `LOW` / `0.125` | Payload byte sum is outside the learned per-ID range.                 | Payload values differ from normal range.                         |
| `rule_spoofing_known_id_payload_jump_outside_profile` |   `LOW` / `0.125` | Hamming distance exceeds the per-ID or global high threshold.         | Payload changes too much compared with previous same-ID traffic. |

Most spoofing rules are intentionally weak. Except for a DLC mismatch, multiple symptoms are generally required to reach the default attack threshold.

---

## 16. Masquerade Rule

Masquerade packets may look valid in isolation:

- The CAN ID is known.
- The DLC is valid.
- The payload may have appeared before.
- Timing may not be obviously impossible.

The implemented masquerade rule is:

| Rule flag                                             |             Score | Condition                                                                                                                                                                         | Intuition                                                                             |
| ----------------------------------------------------- | ----------------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `rule_masquerade_stale_payload_reuse_for_periodic_id` | `TRIGGER` / `0.5` | A frequent, fast-periodic, payload-stable known ID reuses an exact payload after a longer-than-normal benign reuse gap while its same-ID rate is at least its median benign rate. | A valid-looking periodic ID is reusing stale payload content in a suspicious context. |

The rule condition combines several training-derived checks:

```python
periodic_static_id = (
    id_known
    & (id_observation_count >= frequent_id_count_threshold)
    & (id_delta_median > 0)
    & (id_delta_median <= periodic_id_delta_threshold)
    & (id_hamming_median <= static_payload_hamming_threshold)
)

stale_payload_reuse = (
    periodic_static_id
    & reuse_gap_profile_available
    & (same_id_rate_last_time_window_hz >= id_rate_median)
    & (payload_reuse_gap_same_id_s > id_payload_reuse_gap_high)
)
```

---

## 17. Replay-Like Rules

Replay is treated as an exact duplicate payload for a known ID arriving earlier than expected.

| Rule flag                                       |             Score | Condition                                                                              | Intuition                                           |
| ----------------------------------------------- | ----------------: | -------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `rule_replay_duplicate_payload_too_early`       |  `HIGH` / `0.375` | Same-ID hamming distance is `0` and same-ID timing is below the learned low threshold. | Exact duplicate payload arrives too soon.           |
| `rule_replay_duplicate_payload_with_rate_spike` | `MEDIUM` / `0.25` | Duplicate payload arrives too soon and same-ID rate exceeds the per-ID high threshold. | Duplicate replay behavior also causes a rate spike. |

The second replay rule is stricter and implies the first condition. Therefore, when the rate-spike replay rule fires, the replay score normally becomes:

```text
0.375 + 0.25 = 0.625
```

This exceeds the default attack threshold of `0.5`.

---
