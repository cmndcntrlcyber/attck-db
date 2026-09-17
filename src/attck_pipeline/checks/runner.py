from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from loguru import logger


class DataQualityError(Exception):
    def __init__(self, failures: list[CheckResult]):
        self.failures = failures
        messages = [f"[{f.severity}] {f.name}: {f.message}" for f in failures]
        super().__init__(f"{len(failures)} check(s) failed:\n" + "\n".join(messages))


@dataclass
class CheckResult:
    name: str
    passed: bool
    severity: str
    message: str
    details: dict = field(default_factory=dict)


class CheckRunner:
    def __init__(self, checks: list[Callable]):
        self.checks = checks

    def run(self, **context) -> list[CheckResult]:
        results = []
        for check_fn in self.checks:
            try:
                result = check_fn(**context)
                results.append(result)
                status = "PASS" if result.passed else f"FAIL ({result.severity})"
                logger.info(f"  [{status}] {result.name}: {result.message}")
            except Exception as e:
                results.append(CheckResult(
                    name=check_fn.__name__,
                    passed=False,
                    severity="error",
                    message=f"Check raised exception: {e}",
                ))
        return results

    def run_or_raise(self, **context) -> list[CheckResult]:
        results = self.run(**context)
        failures = [r for r in results if not r.passed and r.severity == "error"]
        if failures:
            raise DataQualityError(failures)
        return results
