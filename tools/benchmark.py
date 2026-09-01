#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import math
import os
import re
import stat
import statistics
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

PINNED_WASM_SIZE = 297_238
PINNED_WASM_SHA256 = "b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4"
COMPARABLE_NAMES = (
    "ColdStart",
    "CredentialRoundTrip",
    "RuntimeFields",
    "ModelCacheDecrypt",
    "ContextNew",
    "InferHot",
)
NATIVE_NAMES = ("ColdStart", "BodyRoundTrip", *COMPARABLE_NAMES[1:])


class BenchmarkError(Exception):
    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class Sample:
    ns_per_op: float
    bytes_per_op: int
    allocs_per_op: int


@dataclass(frozen=True)
class Summary:
    median_ns: float
    min_ns: float
    max_ns: float
    median_bytes: float
    median_allocs: float

    @property
    def ops_per_second(self) -> float:
        return 1_000_000_000.0 / self.median_ns

    @property
    def spread_percent(self) -> float:
        return (self.max_ns - self.min_ns) / self.median_ns * 100.0


@dataclass(frozen=True)
class BenchmarkEnvironment:
    goos: str
    goarch: str
    cpu: str


@dataclass(frozen=True)
class Metadata:
    generated_utc: str
    commit: str
    dirty: bool
    go_version: str
    goos: str
    goarch: str
    cpu: str
    wazero_version: str
    fixture_version: str
    wasm_hash: str
    count: int
    benchtime: str


@dataclass(frozen=True)
class BenchmarkConfig:
    repo: Path
    wasm: Path
    fixtures: Path
    output: Path
    count: int
    benchtime: str


_BENCHMARK_LINE = re.compile(
    r"^(?P<prefix>BenchmarkCompare(?:Native|WASM)/)"
    r"(?P<name>[A-Za-z][A-Za-z0-9]*)"
    r"(?:-\d+)?\s+\d+\s+"
    r"(?P<ns>(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)\s+ns/op\s+"
    r"(?P<bytes>\d+)\s+B/op\s+"
    r"(?P<allocs>\d+)\s+allocs/op$"
)


def parse_benchmark_output(
    text: str,
    *,
    prefix: str,
    expected_names: set[str],
    count: int,
) -> tuple[dict[str, list[Sample]], BenchmarkEnvironment]:
    if count <= 0 or not expected_names:
        raise BenchmarkError("benchmark-configuration")
    samples: dict[str, list[Sample]] = {name: [] for name in expected_names}
    goos = ""
    goarch = ""
    cpu = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("goos:"):
            goos = line.removeprefix("goos:").strip()
            continue
        if line.startswith("goarch:"):
            goarch = line.removeprefix("goarch:").strip()
            continue
        if line.startswith("cpu:"):
            cpu = line.removeprefix("cpu:").strip()
            continue
        if line.startswith("pkg:") or line == "PASS" or line.startswith("ok\t") or line.startswith("ok  "):
            continue
        if not line.startswith("Benchmark"):
            continue
        match = _BENCHMARK_LINE.fullmatch(line)
        if match is None:
            raise BenchmarkError("benchmark-output")
        if match.group("prefix") != prefix:
            raise BenchmarkError("benchmark-prefix")
        name = match.group("name")
        if name not in expected_names:
            raise BenchmarkError("benchmark-name")
        ns_per_op = float(match.group("ns"))
        bytes_per_op = int(match.group("bytes"))
        allocs_per_op = int(match.group("allocs"))
        if not math.isfinite(ns_per_op) or ns_per_op <= 0 or bytes_per_op < 0 or allocs_per_op < 0:
            raise BenchmarkError("benchmark-value")
        samples[name].append(Sample(ns_per_op, bytes_per_op, allocs_per_op))
    if not goos or not goarch or not cpu:
        raise BenchmarkError("benchmark-environment")
    if any(len(values) != count for values in samples.values()):
        raise BenchmarkError("benchmark-sample-count")
    return samples, BenchmarkEnvironment(goos=goos, goarch=goarch, cpu=cpu)


def summarize(samples: list[Sample]) -> Summary:
    if not samples:
        raise BenchmarkError("benchmark-sample-count")
    ns_values = [sample.ns_per_op for sample in samples]
    byte_values = [sample.bytes_per_op for sample in samples]
    allocation_values = [sample.allocs_per_op for sample in samples]
    return Summary(
        median_ns=float(statistics.median(ns_values)),
        min_ns=min(ns_values),
        max_ns=max(ns_values),
        median_bytes=float(statistics.median(byte_values)),
        median_allocs=float(statistics.median(allocation_values)),
    )


def speedup(native: Summary, wasm: Summary) -> float:
    value = wasm.median_ns / native.median_ns
    if not math.isfinite(value) or value <= 0:
        raise BenchmarkError("benchmark-ratio")
    return value


def validate_wasm(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise BenchmarkError("wasm-read") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BenchmarkError("wasm-file-type")
    if info.st_size != PINNED_WASM_SIZE:
        raise BenchmarkError("wasm-size")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(64 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise BenchmarkError("wasm-read") from exc
    if digest.hexdigest() != PINNED_WASM_SHA256:
        raise BenchmarkError("wasm-hash")


def _format_duration(ns_per_op: float) -> str:
    if ns_per_op < 1_000:
        return f"{ns_per_op:.2f} ns"
    if ns_per_op < 1_000_000:
        return f"{ns_per_op / 1_000:.3f} µs"
    if ns_per_op < 1_000_000_000:
        return f"{ns_per_op / 1_000_000:.3f} ms"
    return f"{ns_per_op / 1_000_000_000:.3f} s"


def _format_number(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f}M"
    if value >= 1_000:
        return f"{value / 1_000:.2f}K"
    return f"{value:.2f}"


def _format_integral_median(value: float) -> str:
    if value.is_integer():
        return f"{int(value):,}"
    return f"{value:,.1f}"


def render_report(
    metadata: Metadata,
    native: dict[str, Summary],
    wasm: dict[str, Summary],
) -> str:
    missing_native = set(NATIVE_NAMES) - native.keys()
    missing_wasm = set(COMPARABLE_NAMES) - wasm.keys()
    if missing_native or missing_wasm:
        raise BenchmarkError("benchmark-summary")
    dirty = "dirty" if metadata.dirty else "clean"
    short_commit = metadata.commit[:12]
    lines = [
        "# Native vs WASM Benchmark",
        "",
        "> 本文档由 `tools/benchmark.py` 使用 frozen synthetic fixtures 自动生成。数据是性能证据，不是 pass/fail 阈值。",
        "",
        "## Snapshot",
        "",
        f"- generated (UTC): `{metadata.generated_utc}`",
        f"- source commit: `{short_commit}`",
        f"- working tree: {dirty}",
        f"- Go: `{metadata.go_version}`",
        f"- platform: `{metadata.goos}/{metadata.goarch}`",
        f"- CPU: `{metadata.cpu}`",
        f"- wazero: `{metadata.wazero_version}`",
        f"- fixture/oracle version: `{metadata.fixture_version}`",
        f"- external WASM SHA-256: `{metadata.wasm_hash}…`",
        f"- sampling: `GOMAXPROCS=1`, `-cpu=1`, `-benchtime={metadata.benchtime}`, `-count={metadata.count}`",
        "",
        "## Methodology",
        "",
        "Native 和 WASM benchmark 严格串行运行，并使用同一组 Qoder 1.1.34 frozen synthetic fixtures、确定性 clock 与 entropy transcript。表中数值为各轮样本的中位数。",
        "",
        "- `ColdStart`：只比较 protocol backend construction 与 close；不含外部 WASM 文件读取，也不是完整应用启动时间。",
        "- `CredentialRoundTrip`：credential encrypt + decrypt。",
        "- `RuntimeFields`：从 typed semantic input 生成 runtime auth fields；WASM 侧包含 JSON boundary。",
        "- `ModelCacheDecrypt`：解密同一 frozen QMC v1 envelope。",
        "- `ContextNew`：context construction + close/free。",
        "- `InferHot`：复用已创建的 backend/module 和 context，仅测一次完整 request preparation。",
        "- `BodyRoundTrip`：Native-only encode + decode；pinned WASM 没有 standalone WASM export，WASM body 成本包含在 `InferHot` 中。",
        "",
        "## Execution Time",
        "",
        "| Operation | Native median | WASM median | Native ops/s | WASM ops/s | Native speedup |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name in COMPARABLE_NAMES:
        native_summary = native[name]
        wasm_summary = wasm[name]
        lines.append(
            "| "
            + name
            + " | "
            + _format_duration(native_summary.median_ns)
            + " | "
            + _format_duration(wasm_summary.median_ns)
            + " | "
            + _format_number(native_summary.ops_per_second)
            + " | "
            + _format_number(wasm_summary.ops_per_second)
            + " | "
            + f"{speedup(native_summary, wasm_summary):.2f}× |"
        )
    lines.extend(
        [
            "",
            "## Go-host Allocations",
            "",
            "| Operation | Native B/op | WASM host B/op | Native allocs/op | WASM host allocs/op |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for name in COMPARABLE_NAMES:
        native_summary = native[name]
        wasm_summary = wasm[name]
        lines.append(
            f"| {name} | {_format_integral_median(native_summary.median_bytes)} | "
            f"{_format_integral_median(wasm_summary.median_bytes)} | "
            f"{_format_integral_median(native_summary.median_allocs)} | "
            f"{_format_integral_median(wasm_summary.median_allocs)} |"
        )
    body = native["BodyRoundTrip"]
    lines.extend(
        [
            "",
            "## Native-only Body Codec",
            "",
            f"`BodyRoundTrip`: **{_format_duration(body.median_ns)}**, "
            f"{_format_integral_median(body.median_bytes)} B/op, "
            f"{_format_integral_median(body.median_allocs)} allocs/op.",
            "",
            "## Variability",
            "",
            "| Operation | Native min / median / max | Native spread | WASM min / median / max | WASM spread |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for name in COMPARABLE_NAMES:
        native_summary = native[name]
        wasm_summary = wasm[name]
        lines.append(
            f"| {name} | {_format_duration(native_summary.min_ns)} / "
            f"{_format_duration(native_summary.median_ns)} / {_format_duration(native_summary.max_ns)} | "
            f"{native_summary.spread_percent:.2f}% | "
            f"{_format_duration(wasm_summary.min_ns)} / {_format_duration(wasm_summary.median_ns)} / "
            f"{_format_duration(wasm_summary.max_ns)} | {wasm_summary.spread_percent:.2f}% |"
        )
    lines.extend(
        [
            "",
            "## Interpretation and Limitations",
            "",
            "1. WASM 的 `B/op` / `allocs/op` 仅统计 Go host heap；不包含 guest linear memory 内部的分配、增长或拷贝。",
            "2. `ColdStart` 的巨大差异反映 native service wiring 与 WASM validation/compile/instantiate 的不同工作量；它不代表完整应用启动时间。",
            "3. WASM hot-path 结果排除了 module 初始化；`InferHot` 也排除了 context construction。",
            "4. 网络 I/O、上游延迟、credential/catalog 文件 I/O 均不在这些 microbenchmarks 中。",
            "5. 所有输入均为 synthetic fixtures；benchmark 不读取真实 credential、token、请求或响应。",
            "",
            "## Reproduce",
            "",
            "```bash",
            "python3 tools/benchmark.py --wasm /authorized/path/qoder_auth.wasm",
            "```",
            "",
            "可用 `--count` 与 `--benchtime` 覆盖默认采样参数。runner 会验证外部 WASM 的 pinned size/SHA，Native 与 WASM 串行执行，并在两侧都成功后原子更新本文件。",
            "",
        ]
    )
    return "\n".join(lines)


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as destination:
            destination.write(text)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_command(args: list[str], cwd: Path, env: dict[str, str], category: str) -> str:
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BenchmarkError(category) from exc
    if completed.returncode != 0:
        raise BenchmarkError(category)
    return completed.stdout


def _metadata_command(args: list[str], cwd: Path, category: str) -> str:
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BenchmarkError(category) from exc
    if completed.returncode != 0:
        raise BenchmarkError(category)
    return completed.stdout.strip()


def parse_wazero_version(go_mod_text: str) -> str:
    match = re.search(
        r"(?m)^\s*(?:require\s+)?github\.com/tetratelabs/wazero\s+(v\S+)\s*$",
        go_mod_text,
    )
    if match is None:
        raise BenchmarkError("metadata-wazero")
    return match.group(1)


def collect_metadata(config: BenchmarkConfig, environment: BenchmarkEnvironment) -> Metadata:
    commit = _metadata_command(["git", "rev-parse", "HEAD"], config.repo, "metadata-git")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise BenchmarkError("metadata-git")
    dirty = bool(_metadata_command(["git", "status", "--porcelain"], config.repo, "metadata-git"))
    go_version = _metadata_command(["go", "version"], config.repo, "metadata-go")
    go_mod = config.repo / "tools" / "wasm_oracle" / "go.mod"
    try:
        go_mod_text = go_mod.read_text(encoding="utf-8")
    except OSError as exc:
        raise BenchmarkError("metadata-wazero") from exc
    wazero_version = parse_wazero_version(go_mod_text)
    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return Metadata(
        generated_utc=generated,
        commit=commit,
        dirty=dirty,
        go_version=go_version,
        goos=environment.goos,
        goarch=environment.goarch,
        cpu=environment.cpu,
        wazero_version=wazero_version,
        fixture_version="1.1.34",
        wasm_hash=PINNED_WASM_SHA256[:12],
        count=config.count,
        benchtime=config.benchtime,
    )


def _validate_config(config: BenchmarkConfig) -> None:
    if config.count <= 0 or config.count > 100:
        raise BenchmarkError("benchmark-count")
    if re.fullmatch(r"(?:[1-9]\d*x|(?:\d+(?:\.\d+)?)(?:ns|us|µs|ms|s|m|h))", config.benchtime) is None:
        raise BenchmarkError("benchmark-benchtime")
    if not config.repo.is_dir():
        raise BenchmarkError("repository")
    if not config.fixtures.is_dir():
        raise BenchmarkError("fixture-directory")


def generate_benchmark_report(
    config: BenchmarkConfig,
    *,
    command_runner=run_command,
    metadata_collector=collect_metadata,
) -> Path:
    _validate_config(config)
    validate_wasm(config.wasm)

    base_env = dict(os.environ)
    native_env = dict(base_env)
    native_env.update({"GOMAXPROCS": "1", "GOWORK": "off", "GOPROXY": "off", "GOFLAGS": ""})
    native_env.pop("QODER2API_BENCH_WASM", None)
    native_env["QODER2API_BENCH_FIXTURES"] = str(config.fixtures)
    native_args = [
        "go",
        "test",
        ".",
        "-run",
        "^$",
        "-bench",
        "^BenchmarkCompareNative/",
        "-benchmem",
        "-benchtime",
        config.benchtime,
        "-count",
        str(config.count),
        "-cpu",
        "1",
        "-timeout",
        "30m",
    ]
    native_output = command_runner(native_args, config.repo, native_env, "native-benchmark-failed")
    native_samples, native_environment = parse_benchmark_output(
        native_output,
        prefix="BenchmarkCompareNative/",
        expected_names=set(NATIVE_NAMES),
        count=config.count,
    )

    wasm_env = dict(base_env)
    wasm_env.update(
        {
            "GOMAXPROCS": "1",
            "GOWORK": "off",
            "GOPROXY": "off",
            "GOFLAGS": "",
            "QODER2API_BENCH_WASM": str(config.wasm),
            "QODER2API_BENCH_FIXTURES": str(config.fixtures),
        }
    )
    wasm_args = [
        "go",
        "-C",
        "tools/wasm_oracle",
        "test",
        "-run",
        "^$",
        "-bench",
        "^BenchmarkCompareWASM/",
        "-benchmem",
        "-benchtime",
        config.benchtime,
        "-count",
        str(config.count),
        "-cpu",
        "1",
        "-timeout",
        "30m",
    ]
    wasm_output = command_runner(wasm_args, config.repo, wasm_env, "wasm-benchmark-failed")
    wasm_samples, wasm_environment = parse_benchmark_output(
        wasm_output,
        prefix="BenchmarkCompareWASM/",
        expected_names=set(COMPARABLE_NAMES),
        count=config.count,
    )
    if native_environment != wasm_environment:
        raise BenchmarkError("benchmark-environment-mismatch")

    native_summaries = {name: summarize(values) for name, values in native_samples.items()}
    wasm_summaries = {name: summarize(values) for name, values in wasm_samples.items()}
    metadata = metadata_collector(config, native_environment)
    report = render_report(metadata, native_summaries, wasm_summaries)
    atomic_write(config.output, report)
    return config.output


def _absolute_path(value: str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(value)))


def parse_args(argv: list[str] | None = None) -> BenchmarkConfig:
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Benchmark native Qoder protocol against an authorized external WASM oracle")
    parser.add_argument("--wasm", required=True, help="authorized pinned qoder_auth WASM path")
    parser.add_argument("--fixtures", default=str(repo / "testdata/protocol/1.1.34"))
    parser.add_argument("--output", default=str(repo / "BENCHMARK.md"))
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--benchtime", default="1s")
    args = parser.parse_args(argv)
    return BenchmarkConfig(
        repo=repo,
        wasm=_absolute_path(args.wasm),
        fixtures=_absolute_path(args.fixtures),
        output=_absolute_path(args.output),
        count=args.count,
        benchtime=args.benchtime,
    )


def main(argv: list[str] | None = None) -> int:
    try:
        config = parse_args(argv)
        output = generate_benchmark_report(config)
    except BenchmarkError as exc:
        print(f"benchmark result=FAIL category={exc.category}", file=sys.stderr)
        return 1
    except Exception:
        print("benchmark result=FAIL category=internal", file=sys.stderr)
        return 1
    print(f"benchmark result=PASS report={output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
