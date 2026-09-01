#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import io
import math
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark


class BenchmarkRunnerTests(unittest.TestCase):
    def test_parse_requires_exact_sample_count(self) -> None:
        output = "\n".join(
            [
                "goos: linux",
                "goarch: amd64",
                "pkg: synthetic",
                "cpu: Synthetic CPU",
                "BenchmarkCompareNative/CredentialRoundTrip-1 1000 1200 ns/op 3440 B/op 15 allocs/op",
                "PASS",
                "ok  synthetic  1.0s",
            ]
        )
        with self.assertRaisesRegex(benchmark.BenchmarkError, "benchmark-sample-count"):
            benchmark.parse_benchmark_output(
                output,
                prefix="BenchmarkCompareNative/",
                expected_names={"CredentialRoundTrip"},
                count=2,
            )

    def test_parse_accepts_optional_cpu_suffix(self) -> None:
        output = "\n".join(
            [
                "goos: linux",
                "goarch: amd64",
                "pkg: synthetic",
                "cpu: Synthetic CPU",
                "BenchmarkCompareNative/CredentialRoundTrip 1000 1200 ns/op 3440 B/op 15 allocs/op",
                "BenchmarkCompareNative/CredentialRoundTrip-1 1000 1400 ns/op 3440 B/op 15 allocs/op",
                "PASS",
                "ok  synthetic  1.0s",
            ]
        )
        samples, environment = benchmark.parse_benchmark_output(
            output,
            prefix="BenchmarkCompareNative/",
            expected_names={"CredentialRoundTrip"},
            count=2,
        )
        self.assertEqual([sample.ns_per_op for sample in samples["CredentialRoundTrip"]], [1200.0, 1400.0])
        self.assertEqual(environment.goos, "linux")
        self.assertEqual(environment.goarch, "amd64")
        self.assertEqual(environment.cpu, "Synthetic CPU")

    def test_parse_rejects_unknown_benchmark_name(self) -> None:
        output = "\n".join(
            [
                "goos: linux",
                "goarch: amd64",
                "pkg: synthetic",
                "cpu: Synthetic CPU",
                "BenchmarkCompareNative/Unexpected-1 1000 1200 ns/op 1 B/op 1 allocs/op",
                "PASS",
                "ok  synthetic  1.0s",
            ]
        )
        with self.assertRaisesRegex(benchmark.BenchmarkError, "benchmark-name"):
            benchmark.parse_benchmark_output(
                output,
                prefix="BenchmarkCompareNative/",
                expected_names={"CredentialRoundTrip"},
                count=1,
            )

    def test_summarize_uses_median_and_computes_speedup(self) -> None:
        native = benchmark.summarize(
            [
                benchmark.Sample(100.0, 10, 1),
                benchmark.Sample(200.0, 20, 2),
                benchmark.Sample(300.0, 30, 3),
            ]
        )
        wasm = benchmark.summarize(
            [
                benchmark.Sample(1000.0, 40, 4),
                benchmark.Sample(2000.0, 50, 5),
                benchmark.Sample(3000.0, 60, 6),
            ]
        )
        self.assertEqual(native.median_ns, 200.0)
        self.assertEqual(native.median_bytes, 20.0)
        self.assertEqual(native.median_allocs, 2.0)
        self.assertEqual(benchmark.speedup(native, wasm), 10.0)
        self.assertTrue(math.isfinite(native.ops_per_second))

    def test_validate_wasm_rejects_wrong_size_without_printing_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorized-oracle.wasm"
            path.write_bytes(b"not-the-pinned-oracle")
            with self.assertRaises(benchmark.BenchmarkError) as caught:
                benchmark.validate_wasm(path)
            self.assertEqual(caught.exception.category, "wasm-size")
            self.assertNotIn(str(path), str(caught.exception))

    def test_parse_wazero_version_accepts_single_line_require(self) -> None:
        go_mod = "module synthetic\n\ngo 1.25.0\n\nrequire github.com/tetratelabs/wazero v1.12.0\n"
        self.assertEqual(benchmark.parse_wazero_version(go_mod), "v1.12.0")

    def test_render_documents_memory_limitations(self) -> None:
        metadata = benchmark.Metadata(
            generated_utc="2026-09-01T00:00:00Z",
            commit="0123456789abcdef0123456789abcdef01234567",
            dirty=True,
            go_version="go version go1.25.0 linux/amd64",
            goos="linux",
            goarch="amd64",
            cpu="Synthetic CPU",
            wazero_version="v1.12.0",
            fixture_version="1.1.34",
            wasm_hash="b3ddd7c9235c",
            count=3,
            benchtime="1s",
        )
        native = {
            "ColdStart": benchmark.Summary(100.0, 90.0, 110.0, 10.0, 1.0),
            "BodyRoundTrip": benchmark.Summary(200.0, 190.0, 210.0, 20.0, 2.0),
            "CredentialRoundTrip": benchmark.Summary(300.0, 290.0, 310.0, 30.0, 3.0),
            "RuntimeFields": benchmark.Summary(400.0, 390.0, 410.0, 40.0, 4.0),
            "ModelCacheDecrypt": benchmark.Summary(500.0, 490.0, 510.0, 50.0, 5.0),
            "ContextNew": benchmark.Summary(600.0, 590.0, 610.0, 60.0, 6.0),
            "InferHot": benchmark.Summary(700.0, 690.0, 710.0, 70.0, 7.0),
        }
        wasm = {
            name: benchmark.Summary(
                summary.median_ns * 10,
                summary.min_ns * 10,
                summary.max_ns * 10,
                summary.median_bytes * 2,
                summary.median_allocs * 2,
            )
            for name, summary in native.items()
            if name != "BodyRoundTrip"
        }
        report = benchmark.render_report(metadata, native, wasm)
        self.assertIn("guest linear memory", report)
        self.assertIn("protocol backend construction", report)
        self.assertIn("standalone WASM export", report)
        self.assertIn("10.00×", report)
        self.assertIn("working tree: dirty", report)
        self.assertNotIn("/home/", report)

    def test_atomic_write_replaces_existing_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "BENCHMARK.md"
            path.write_text("old", encoding="utf-8")
            benchmark.atomic_write(path, "new\n")
            self.assertEqual(path.read_text(encoding="utf-8"), "new\n")

    def test_generate_runs_native_before_wasm_with_isolated_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wasm = root / "oracle.wasm"
            fixtures = root / "fixtures"
            output = root / "BENCHMARK.md"
            wasm.write_bytes(b"synthetic")
            fixtures.mkdir()
            config = benchmark.BenchmarkConfig(
                repo=root,
                wasm=wasm,
                fixtures=fixtures,
                output=output,
                count=2,
                benchtime="1s",
            )
            calls: list[tuple[list[str], Path, dict[str, str]]] = []

            def command_runner(args: list[str], cwd: Path, env: dict[str, str], category: str) -> str:
                calls.append((args, cwd, env))
                if len(calls) == 1:
                    return benchmark_output("BenchmarkCompareNative/", set(benchmark.NATIVE_NAMES), 2)
                return benchmark_output("BenchmarkCompareWASM/", set(benchmark.COMPARABLE_NAMES), 2)

            metadata = fixed_metadata(count=2)
            with mock.patch.object(benchmark, "validate_wasm"):
                generated = benchmark.generate_benchmark_report(
                    config,
                    command_runner=command_runner,
                    metadata_collector=lambda *_: metadata,
                )
            self.assertEqual(generated, output)
            self.assertEqual(len(calls), 2)
            self.assertIn("^BenchmarkCompareNative/", calls[0][0])
            self.assertIn("^BenchmarkCompareWASM/", calls[1][0])
            self.assertEqual(calls[0][2]["GOMAXPROCS"], "1")
            self.assertEqual(calls[0][2]["GOWORK"], "off")
            self.assertEqual(calls[0][2]["GOPROXY"], "off")
            self.assertEqual(calls[0][2]["GOFLAGS"], "")
            self.assertNotIn("QODER2API_BENCH_WASM", calls[0][2])
            self.assertEqual(calls[0][2]["QODER2API_BENCH_FIXTURES"], str(fixtures))
            self.assertEqual(calls[1][2]["GOWORK"], "off")
            self.assertEqual(calls[1][2]["GOPROXY"], "off")
            self.assertEqual(calls[1][2]["GOFLAGS"], "")
            self.assertEqual(calls[1][2]["QODER2API_BENCH_WASM"], str(wasm))
            self.assertEqual(calls[1][2]["QODER2API_BENCH_FIXTURES"], str(fixtures))
            self.assertIn("Native vs WASM Benchmark", output.read_text(encoding="utf-8"))

    def test_failed_wasm_does_not_replace_existing_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wasm = root / "oracle.wasm"
            fixtures = root / "fixtures"
            output = root / "BENCHMARK.md"
            wasm.write_bytes(b"synthetic")
            fixtures.mkdir()
            output.write_text("existing\n", encoding="utf-8")
            config = benchmark.BenchmarkConfig(root, wasm, fixtures, output, 1, "10x")
            calls = 0

            def command_runner(args: list[str], cwd: Path, env: dict[str, str], category: str) -> str:
                nonlocal calls
                calls += 1
                if calls == 1:
                    return benchmark_output("BenchmarkCompareNative/", set(benchmark.NATIVE_NAMES), 1)
                raise benchmark.BenchmarkError("wasm-benchmark-failed")

            with mock.patch.object(benchmark, "validate_wasm"):
                with self.assertRaisesRegex(benchmark.BenchmarkError, "wasm-benchmark-failed"):
                    benchmark.generate_benchmark_report(
                        config,
                        command_runner=command_runner,
                        metadata_collector=lambda *_: fixed_metadata(count=1, benchtime="10x"),
                    )
            self.assertEqual(output.read_text(encoding="utf-8"), "existing\n")

    def test_cli_error_does_not_disclose_wasm_path(self) -> None:
        secret_path = "/synthetic/private/oracle.wasm"
        stderr = io.StringIO()
        with mock.patch.object(
            benchmark,
            "generate_benchmark_report",
            side_effect=benchmark.BenchmarkError("wasm-hash"),
        ):
            with contextlib.redirect_stderr(stderr):
                status = benchmark.main(["--wasm", secret_path])
        self.assertEqual(status, 1)
        self.assertEqual(stderr.getvalue(), "benchmark result=FAIL category=wasm-hash\n")
        self.assertNotIn(secret_path, stderr.getvalue())


def benchmark_output(prefix: str, names: set[str], count: int) -> str:
    lines = ["goos: linux", "goarch: amd64", "pkg: synthetic", "cpu: Synthetic CPU"]
    for name in sorted(names):
        for index in range(count):
            lines.append(
                f"{prefix}{name}-1 1000 {1000 + index} ns/op {100 + index} B/op {10 + index} allocs/op"
            )
    lines.extend(["PASS", "ok  synthetic  1.0s"])
    return "\n".join(lines)


def fixed_metadata(*, count: int, benchtime: str = "1s") -> benchmark.Metadata:
    return benchmark.Metadata(
        generated_utc="2026-09-01T00:00:00Z",
        commit="0123456789abcdef0123456789abcdef01234567",
        dirty=True,
        go_version="go version go1.25.0 linux/amd64",
        goos="linux",
        goarch="amd64",
        cpu="Synthetic CPU",
        wazero_version="v1.12.0",
        fixture_version="1.1.34",
        wasm_hash="b3ddd7c9235c",
        count=count,
        benchtime=benchtime,
    )


if __name__ == "__main__":
    unittest.main()
