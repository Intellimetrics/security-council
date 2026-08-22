"""Eval harness (R3 lane 1): replay-based ground-truth gate for the scorer/policy.

`metrics.py` matches merged findings against `EXPECTED.yaml` and computes the
gate; `runner.py` replays the recorded raw fixtures through the real pipeline.
Calibration fitting is deliberately NOT here yet — see HANDOFF §8.5.
"""
