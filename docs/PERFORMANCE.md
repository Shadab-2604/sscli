# Scan Performance & Adaptive Concurrency Engine

The **Intelligent Concurrency Manager** coordinates CPU, memory, and battery telemetry to throttle workload dynamically without degrading system responsiveness.

---

## 1. Concurrency Models

`systemscan` supports three distinct concurrency paradigms:

1. **`ADAPTIVE` (Default)**:
   - Evaluates physical core count (avoiding hyperthreading oversubscription during disk I/O).
   - Monitors CPU load, RAM pressure, and battery level via `psutil`.
   - Automatically throttles worker threads by 50% when CPU load exceeds `max_cpu_percent` (default 85%) or memory exceeds `max_memory_percent` (default 75%).
   - Restricts workers to 1 thread when running on battery power below 20%.

2. **`FIXED`**:
   - Runs with a strictly defined worker pool count (1 to 64 threads) regardless of host resource usage.

3. **`SEQUENTIAL`**:
   - Single-threaded execution mode. Eliminates threading overhead for low-resource environments, single-core VPS containers, or debugging.

---

## 2. Resource Ceilings & Throttling Logic

```
   Host CPU / RAM Metric
            |
            v
  Exceeds Max Ceiling? (e.g. CPU > 85%, RAM > 75%)
         /     \
       YES      NO
       /         \
Reduce workers   Maintain base workers:
by 50%           min(physical_cores, max_workers)
       \         /
        v       v
   Battery < 20%?
      /      \
    YES       NO
    /          \
Clamp to 1    Dispatch Workload
```

---

## 3. Dynamic ETA Engine (`IntelligentETAEngine`)

Dynamic time estimates avoid naive progress reporting through the following safeguards:

- **Guard Against Unknown Totals**: When total items/bytes have not yet been discovered (directory traversal underway), ETA and percentage completion remain `None`. The system will **never** fabricate arbitrary percentages.
- **Minimum Sampling Gate**: A minimum threshold of 25 processed items is required before publishing completion forecasts to prevent wild swings.
- **Exponential Moving Average (EMA)**:
  $$\text{EMA}_t = \alpha \cdot \text{Rate}_{\text{instant}} + (1 - \alpha) \cdot \text{EMA}_{t-1}$$
  Default smoothing factor $\alpha = 0.20$ dampens temporary throughput spikes caused by scanning small metadata-only files.

---

## 4. Performance Inspection CLI

Inspect current host telemetry, core counts, and concurrency ceilings:

```bash
# Human-readable Rich panel
systemscan performance

# Machine-readable JSON telemetry
systemscan performance --format json
```

