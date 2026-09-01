# Native vs WASM Benchmark

> 本文档由 `tools/benchmark.py` 使用 frozen synthetic fixtures 自动生成。数据是性能证据，不是 pass/fail 阈值。

## Snapshot

- generated (UTC): `2026-09-01T06:45:41Z`
- source commit: `c79c82001aa6`
- working tree: dirty
- Go: `go version go1.25.0 linux/amd64`
- platform: `linux/amd64`
- CPU: `AMD Ryzen 9 6900HX with Radeon Graphics`
- wazero: `v1.12.0`
- fixture/oracle version: `1.1.34`
- external WASM SHA-256: `b3ddd7c9235c…`
- sampling: `GOMAXPROCS=1`, `-cpu=1`, `-benchtime=1s`, `-count=10`

## Methodology

Native 和 WASM benchmark 严格串行运行，并使用同一组 Qoder 1.1.34 frozen synthetic fixtures、确定性 clock 与 entropy transcript。表中数值为各轮样本的中位数。

- `ColdStart`：只比较 protocol backend construction 与 close；不含外部 WASM 文件读取，也不是完整应用启动时间。
- `CredentialRoundTrip`：credential encrypt + decrypt。
- `RuntimeFields`：从 typed semantic input 生成 runtime auth fields；WASM 侧包含 JSON boundary。
- `ModelCacheDecrypt`：解密同一 frozen QMC v1 envelope。
- `ContextNew`：context construction + close/free。
- `InferHot`：复用已创建的 backend/module 和 context，仅测一次完整 request preparation。
- `BodyRoundTrip`：Native-only encode + decode；pinned WASM 没有 standalone WASM export，WASM body 成本包含在 `InferHot` 中。

## Execution Time

| Operation | Native median | WASM median | Native ops/s | WASM ops/s | Native speedup |
|---|---:|---:|---:|---:|---:|
| ColdStart | 88.65 ns | 91.070 ms | 11.28M | 10.98 | 1027295.12× |
| CredentialRoundTrip | 1.188 µs | 13.483 µs | 841.40K | 74.16K | 11.34× |
| RuntimeFields | 16.795 µs | 389.954 µs | 59.54K | 2.56K | 23.22× |
| ModelCacheDecrypt | 1.608 µs | 12.633 µs | 621.89K | 79.16K | 7.86× |
| ContextNew | 17.561 µs | 405.505 µs | 56.94K | 2.47K | 23.09× |
| InferHot | 9.155 µs | 38.745 µs | 109.24K | 25.81K | 4.23× |

## Go-host Allocations

| Operation | Native B/op | WASM host B/op | Native allocs/op | WASM host allocs/op |
|---|---:|---:|---:|---:|
| ColdStart | 208 | 15,319,944 | 3 | 30,149 |
| CredentialRoundTrip | 3,440 | 1,088 | 15 | 32 |
| RuntimeFields | 7,728 | 2,656 | 62 | 29 |
| ModelCacheDecrypt | 2,929 | 456 | 25 | 17 |
| ContextNew | 8,688 | 3,168 | 78 | 34 |
| InferHot | 17,128 | 15,712 | 65 | 239 |

## Native-only Body Codec

`BodyRoundTrip`: **3.271 µs**, 10,240 B/op, 6 allocs/op.

## Variability

| Operation | Native min / median / max | Native spread | WASM min / median / max | WASM spread |
|---|---:|---:|---:|---:|
| ColdStart | 87.93 ns / 88.65 ns / 89.55 ns | 1.83% | 89.305 ms / 91.070 ms / 91.813 ms | 2.75% |
| CredentialRoundTrip | 1.182 µs / 1.188 µs / 1.195 µs | 1.09% | 13.473 µs / 13.483 µs / 13.583 µs | 0.82% |
| RuntimeFields | 16.695 µs / 16.795 µs / 16.992 µs | 1.77% | 387.901 µs / 389.954 µs / 391.242 µs | 0.86% |
| ModelCacheDecrypt | 1.599 µs / 1.608 µs / 1.617 µs | 1.12% | 12.547 µs / 12.633 µs / 12.715 µs | 1.33% |
| ContextNew | 17.430 µs / 17.561 µs / 17.728 µs | 1.70% | 404.657 µs / 405.505 µs / 406.980 µs | 0.57% |
| InferHot | 8.914 µs / 9.155 µs / 9.510 µs | 6.51% | 38.293 µs / 38.745 µs / 39.497 µs | 3.11% |

## Interpretation and Limitations

1. WASM 的 `B/op` / `allocs/op` 仅统计 Go host heap；不包含 guest linear memory 内部的分配、增长或拷贝。
2. `ColdStart` 的巨大差异反映 native service wiring 与 WASM validation/compile/instantiate 的不同工作量；它不代表完整应用启动时间。
3. WASM hot-path 结果排除了 module 初始化；`InferHot` 也排除了 context construction。
4. 网络 I/O、上游延迟、credential/catalog 文件 I/O 均不在这些 microbenchmarks 中。
5. 所有输入均为 synthetic fixtures；benchmark 不读取真实 credential、token、请求或响应。

## Reproduce

```bash
python3 tools/benchmark.py --wasm /authorized/path/qoder_auth.wasm
```

可用 `--count` 与 `--benchtime` 覆盖默认采样参数。runner 会验证外部 WASM 的 pinned size/SHA，Native 与 WASM 串行执行，并在两侧都成功后原子更新本文件。
