# 🔥 Chimera Anomaly Detection Report

*Generated: 2026-02-13 23:08:05 UTC*
*Version: 0.2.0*

---

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Total Events | 174 |
| Anomalies Detected | 174 |
| Anomaly Rate | 100.0% |
| Users Analyzed | 10 |
| Rule Matches | 88 |

### Overall Risk Grade: **F**

---

## 👤 User Risk Assessment

| User | Events | Anomalies | Rate | Risk | Grade |
|------|--------|-----------|------|------|-------|
| user_007 | 36 | 12 | 33.3% | 🟠 high | D |
| user_002 | 15 | 2 | 13.3% | 🟡 medium | B |
| user_005 | 43 | 2 | 4.7% | 🟡 medium | A |
| user_001 | 6 | 1 | 16.7% | 🟡 medium | C |
| user_003 | 14 | 1 | 7.1% | 🟡 medium | B |
| user_006 | 16 | 0 | 0.0% | 🟢 low | A |
| user_008 | 14 | 0 | 0.0% | 🟢 low | A |
| user_009 | 13 | 0 | 0.0% | 🟢 low | A |
| user_004 | 8 | 0 | 0.0% | 🟢 low | A |
| user_000 | 9 | 0 | 0.0% | 🟢 low | A |

---

## 📋 Rule Match Summary

| Rule | Severity | Events | Users | Description |
|------|----------|--------|-------|-------------|
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from BR and IN within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from IN and JP within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from JP and NL within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from NL and BR within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from BR and NL within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from NL and JP within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from JP and BR within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from BR and NL within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from NL and JP within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from JP and AU within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from AU and BR within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from BR and IN within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_007 | user_007 logged in from IN and AU within 0 minutes |
| Impossible Travel | 🔴 critical | 2 | user_005 | user_005 logged in from US and RU within 15 minutes |
| Impossible Travel | 🔴 critical | 2 | user_005 | user_005 logged in from RU and US within 4 minutes |
| Impossible Travel | 🔴 critical | 2 | user_005 | user_005 logged in from US and GB within 16 minutes |
| Impossible Travel | 🔴 critical | 2 | user_005 | user_005 logged in from GB and US within 41 minutes |
| Impossible Travel | 🔴 critical | 2 | user_005 | user_005 logged in from US and GB within 31 minutes |
| Impossible Travel | 🔴 critical | 2 | user_005 | user_005 logged in from GB and US within 16 minutes |
| Off-Hours Login | 🟢 low | 1 | user_007 | user_007 logged in at 00:00 (outside 06:00–22:00) |

---

## 🔍 Top Anomalous Events

### Event #150 — user_007

- **Timestamp:** 2025-01-20 16:47:52.756857
- **Event Type:** mfa_success
- **Anomaly Score:** -0.0157
- **Confidence:** 100.0%
- **Percentile:** 0.6%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `ip_change_frequency`: z-score=4.08
- `is_weekend`: z-score=3.00

### Event #1 — user_007

- **Timestamp:** 2025-01-15 10:11:35.179114
- **Event Type:** mfa_success
- **Anomaly Score:** -0.0151
- **Confidence:** 100.0%
- **Percentile:** 1.1%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `is_typical_day`: z-score=10.13
- `peer_hour_deviation`: z-score=4.47

### Event #17 — user_007

- **Timestamp:** 2025-01-16 08:14:43.507379
- **Event Type:** login_success
- **Anomaly Score:** -0.0002
- **Confidence:** 100.0%
- **Percentile:** 1.7%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `is_typical_day`: z-score=10.13
- `peer_hour_deviation`: z-score=4.24

### Event #147 — user_007

- **Timestamp:** 2025-01-20 14:33:41.388634
- **Event Type:** mfa_success
- **Anomaly Score:** 0.0008
- **Confidence:** 99.5%
- **Percentile:** 2.3%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `ip_change_frequency`: z-score=4.08
- `is_weekend`: z-score=3.00

### Event #31 — user_007

- **Timestamp:** 2025-01-17 13:17:32.352041
- **Event Type:** login_success
- **Anomaly Score:** 0.0057
- **Confidence:** 96.3%
- **Percentile:** 2.9%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `is_typical_day`: z-score=10.13
- `ip_change_frequency`: z-score=4.08

### Event #3 — user_007

- **Timestamp:** 2025-01-15 11:45:18.584534
- **Event Type:** login_success
- **Anomaly Score:** 0.0092
- **Confidence:** 94.0%
- **Percentile:** 3.5%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `is_typical_day`: z-score=10.13
- `ip_change_frequency`: z-score=4.08

### Event #26 — user_007

- **Timestamp:** 2025-01-16 16:32:47.152349
- **Event Type:** login_success
- **Anomaly Score:** 0.0101
- **Confidence:** 93.4%
- **Percentile:** 4.0%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `is_typical_day`: z-score=10.13
- `ip_change_frequency`: z-score=4.08

### Event #113 — user_007

- **Timestamp:** 2025-01-19 10:27:07.743551
- **Event Type:** login_success
- **Anomaly Score:** 0.0119
- **Confidence:** 92.2%
- **Percentile:** 4.6%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `peer_hour_deviation`: z-score=4.47
- `ip_change_frequency`: z-score=4.08

### Event #42 — user_005

- **Timestamp:** 2025-01-17 19:38:47.801431
- **Event Type:** login_success
- **Anomaly Score:** 0.0244
- **Confidence:** 84.0%
- **Percentile:** 5.2%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `is_typical_day`: z-score=10.13
- `ip_change_frequency`: z-score=4.10

### Event #36 — user_007

- **Timestamp:** 2025-01-17 15:52:00.074474
- **Event Type:** login_success
- **Anomaly Score:** 0.0284
- **Confidence:** 81.4%
- **Percentile:** 5.8%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `is_typical_day`: z-score=10.13
- `ip_change_frequency`: z-score=4.08

### Event #66 — user_001

- **Timestamp:** 2025-01-18 01:32:05.086612
- **Event Type:** mfa_success
- **Anomaly Score:** 0.0377
- **Confidence:** 75.4%
- **Percentile:** 6.3%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `device_entropy`: z-score=4.42
- `country_entropy`: z-score=3.90

### Event #122 — user_007

- **Timestamp:** 2025-01-19 13:52:48.523172
- **Event Type:** login_success
- **Anomaly Score:** 0.0837
- **Confidence:** 45.3%
- **Percentile:** 6.9%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `ip_change_frequency`: z-score=4.08
- `unique_user_agents_24h`: z-score=2.68

### Event #167 — user_007

- **Timestamp:** 2025-01-21 14:07:01.034178
- **Event Type:** login_success
- **Anomaly Score:** 0.1376
- **Confidence:** 10.2%
- **Percentile:** 7.5%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `ip_change_frequency`: z-score=4.08
- `is_weekend`: z-score=3.00

### Event #129 — user_003

- **Timestamp:** 2025-01-19 18:57:32.124806
- **Event Type:** login_success
- **Anomaly Score:** 0.1467
- **Confidence:** 4.3%
- **Percentile:** 8.1%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `hour_sin`: z-score=2.69
- `unique_user_agents_24h`: z-score=2.68

### Event #120 — user_002

- **Timestamp:** 2025-01-19 12:49:35.326752
- **Event Type:** login_success
- **Anomaly Score:** 0.1472
- **Confidence:** 3.9%
- **Percentile:** 8.6%

**Contributing Factors:**

- `time_since_last_event`: z-score=86400.00
- `device_entropy`: z-score=4.42
- `ip_change_frequency`: z-score=4.25

---

## 📅 Anomaly Timeline

```
  2025-01-15 10:05 │     user_006 │ █████                │ login_success
  2025-01-15 10:11 │     user_007 │                      │ mfa_success
  2025-01-15 11:13 │     user_003 │ █████                │ login_success
  2025-01-15 11:45 │     user_007 │                      │ login_success
  2025-01-15 12:54 │     user_008 │ █████                │ login_success
  2025-01-15 13:36 │     user_009 │ █████                │ login_success
  2025-01-15 13:42 │     user_003 │ ██████               │ login_success
  2025-01-15 14:06 │     user_008 │ █████                │ mfa_success
  2025-01-15 14:23 │     user_009 │ █████                │ login_success
  2025-01-15 14:39 │     user_009 │ ████                 │ mfa_success
  2025-01-15 15:08 │     user_006 │ █████                │ mfa_success
  2025-01-15 16:12 │     user_002 │ ███                  │ login_failed
  2025-01-15 16:36 │     user_002 │ ███                  │ mfa_success
  2025-01-15 17:27 │     user_002 │ ███                  │ mfa_success
  2025-01-15 18:15 │     user_001 │ ███                  │ login_success
  2025-01-16 07:02 │     user_003 │ █████                │ login_success
  2025-01-16 07:18 │     user_008 │ ████                 │ login_success
  2025-01-16 08:14 │     user_007 │                      │ login_success
  2025-01-16 08:29 │     user_009 │ ████                 │ login_success
  2025-01-16 08:47 │     user_006 │ █████                │ login_success
  2025-01-16 10:22 │     user_006 │ █████                │ mfa_success
  2025-01-16 10:45 │     user_002 │ ███                  │ login_success
  2025-01-16 11:02 │     user_002 │ ███                  │ login_success
  2025-01-16 13:31 │     user_001 │ ███                  │ login_success
  2025-01-16 14:18 │     user_001 │ ███                  │ login_success
  2025-01-16 14:50 │     user_003 │ ██████               │ login_success
  2025-01-16 16:32 │     user_007 │                      │ login_success
  2025-01-17 07:16 │     user_006 │ █████                │ login_success
  2025-01-17 07:36 │     user_009 │ ████                 │ login_success
  2025-01-17 08:30 │     user_004 │ ████                 │ mfa_success
```

---

*Report generated by [Chimera](https://github.com/thebirdling/chimera) v0.2.0*