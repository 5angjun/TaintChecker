# TaintChecker
**TaintChekr** is a IDA Plugin that verify the coverage and taint propagation from Taint Analysis Tools.





## Feature
- **Taint Checker** uses [_IDA_](https://hex-rays.com/ida-free/) to visualize the taint analysis.
- The **Taint Checker** follows an LightHouse-like design and can verify Taint Propagation rule with simple logs.
## Requirements

- **Python:** The tested environment is Python 3.9.6.


# Result
You can watch the Taint analysis Coverage and Taint propagation to return value or function arguments.

The darker the green, the more visits to the code section.

### AC18 example
![AC18-example](./assets/image-AC18.png?raw=true)

### W20E example
![W20E-example1](./assets/image-W20E.png?raw=true)
![W20E-example2](./assets/image-W20E-2.png?raw=true)


# Table of Contents
0. [Docker Pull Patched SaTC](#section-0)
1. [Install dependencies](#section-1)
2. [Log the path and taint under this format](#section-2)
3. [Load target Binary and Ctrl+Alt+E](#section-3)

# 0. Docker Pull Patched SaTC <a name="section-0"></a>
- you can apply it for other taint analysis tools.
- In my case, I apply it for [_SaTC_](https://github.com/NSSL-SJTU/SaTC)
```
docker pull psj4618/satc_taint_checker:1.0

docker run -it -v C:\Users\Owner\Desktop\docker-share:/sharing --name taint_check psj4618/satc_taint_checker:1.0

python satc.py -d /home/satc/SaTC/squashfs-root-0 -o /home/satc/res --ghidra_script=ref2sink_cmdi --taint_check

cp ../../*.log /sharing
```


# 1. Install dependencies <a name="section-1"></a>
```
pip install sark
```


# 2. Log the path and taint under this format <a name="section-2"></a>
----------------------------------
[path format](./tests/path.log)
```
0xb045c
0xb0480
0xb04a4
0xf5e4
0xb04c0
0xf5e4
0xb04d8
0xf5e4
0xb04f0
0xf5e4
0xb0510
0xb0510
0xb0528
0xb0534
0xb0534
```

[tainted format](./tests/taint.log)
```
0xb045c r0 tainted
0xf5e4 r0 tainted
0xb0528 r0 tainted
0xb0544 r0 tainted
0xb0640 arg1 tainted (sprintf)
0xf530 r0 tainted
0xf650 r0 tainted
0xb01f4 r0 tainted
0xf530 r0 tainted
0xf650 r0 tainted
0xb0008 r0 tainted
0xb0670 arg1 tainted (sprintf)
0xf530 r0 tainted
0xf650 r0 tainted
0xb0008 r0 tainted
0xf530 r0 tainted
0xf650 r0 tainted

```



# 3. Load target Binary and Ctrl+Alt+E <a name="section-3"></a>
----------------------------------
- you sholud locate `TaintChecker.py` under IDA folder/plugins/
![Fuzz Success](./assets/plugin.png?raw=true)
