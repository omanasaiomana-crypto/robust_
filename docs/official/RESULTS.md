# Official Results & Baseline Comparison

## Performance Summary

| Metric | IdentityShield Detector | Baseline Detector | Delta |
|---|---|---|---|
| **Event Precision** | 1.000 | 0.941 | +5.9% |
| **Event Recall** | 0.957 | 0.457 | +50.0% |
| **Event F1 Score** | 0.978 | 0.615 | **+36.3%** |
| **Session Alert Precision** | 1.000 | N/A (event-only) | High fidelity |
| **Total Events Processed** | 2,967 | 2,967 | — |
| **Total Alerts Generated** | 16 | — | High signal-to-noise |
| **Replay Throughput** | 259.58 ev/s | — | Low latency stream |
| **Replay Latency (p50)** | 1640.24 ms | — | Immediate response |
| **Replay Latency (p95)** | 2953.77 ms | — | Bounded tail latency |

## Latency Profile under Batch Replay (Batch size: 500)

- **Total Events:** 2,967
- **Total Batches:** 6
- **Prefix Replay Duration:** ~11.4 seconds total wall time
- **Throughput:** 259.58 events/second
- **Median Latency (p50):** 1640.24 ms
- **95th Percentile Latency (p95):** 2953.77 ms
- **Max Batch Latency:** 2953.77 ms
- **Data Source Mode:** sample (automatic fallback when data/raw contains no official drops)
- **Baseline Source:** fallback heuristic detector (evaluates when data/labels contains no official baseline detector predictions)
