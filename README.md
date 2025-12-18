# TCP COPA (mvfst-inspired) — Linux Congestion Control Module

This repository contains a Linux TCP congestion control implementation inspired by Meta’s mvfst COPA design.

## Thnings to keep in mind about this implementation

- **Much smaller delta (deltaParam)**  
  The algorithm uses a smaller `delta_param_fp` than mvfst’s default. This reduces delay sensitivity issues that can otherwise overshoot pacing rate and produce abnormal sawtooth behavior (I use fixed point arithmetic which I suspect exacerbates the problem).

- **Bad RTT samples are filtered out**  
  RTT updates ignore invalid and delayed-ACK samples (`rs->rtt_us < 0` or `rs->is_ack_delayed`), so minRTT/standing-RTT tracking is fed with cleaner measurements.

-**Segmentation offloading
  I am fairly confident that this will misbehave when segmentation offloading is present. Beware. 
## RTT signals

- **minRTT**: simple minimum over a configurable window (`copa_min_rtt_win_sec`, default 10s).
- **Standing RTT**: two-half-window min-filter (optional; controlled by `copa_use_rtt_standing`).


## Build 

This module is compiled against the BBRv3 kernel found [here](https://github.com/google/bbr) (the ```v3``` branch).

```bash
make load
make enable 
```
