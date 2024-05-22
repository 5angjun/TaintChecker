# TaintChecker
**TaintChekr** is a IDA Plugin that verify the coverage and taint propagation from Taint Analysis Tools.



<p align="center">
  <a href="https://github.com/0dayResearchLab/kAFL/actions/workflows/CI.yml">
    <img src="https://github.com/0dayResearchLab/kAFL/actions/workflows/CI.yml/badge.svg" alt="CI">
  </a>
</p>

## Feature
- **Taint Checker** uses [_IDA_](https://hex-rays.com/ida-free/) to visualize the taint analysis.
- The **Taint Checker** follows an LightHouse-like design and can verify Taint Propagation rule with simple logs.
## Requirements

- **Python:** The tested environment is Python 3.9.6.
```
pip install sark
```

## How to use

