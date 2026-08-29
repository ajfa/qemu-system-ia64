"""Parser and stream waiter for the structured IA64TEST serial protocol."""

# SPDX-License-Identifier: GPL-2.0-or-later

from dataclasses import dataclass, field
import re
import select
import time
from typing import Callable, Iterable


IDENTIFIER = r"[A-Za-z0-9_.-]+"
CASE_RE = re.compile(
    rf"^IA64TEST suite=(?P<suite>{IDENTIFIER}) "
    rf"case=(?P<case>{IDENTIFIER}) status=(?P<status>PASS|FAIL)"
    r"(?: code=(?P<code>[0-9a-fA-F]+) detail=(?P<detail>[^\r\n]+))?$"
)
DONE_RE = re.compile(
    rf"^IA64TEST suite=(?P<suite>{IDENTIFIER}) status=DONE "
    r"passed=(?P<passed>[0-9]+) failed=(?P<failed>[0-9]+)$"
)


class ProtocolError(AssertionError):
    pass


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    passed: bool
    code: int | None = None
    detail: str | None = None


@dataclass
class SuiteResult:
    suite: str
    cases: dict[str, CaseResult] = field(default_factory=dict)
    passed: int | None = None
    failed: int | None = None
    raw_console: str = ""

    @property
    def done(self) -> bool:
        return self.passed is not None

    def assert_valid(self, required_cases: Iterable[str]) -> None:
        if not self.done:
            raise ProtocolError(f"suite {self.suite!r} did not emit DONE")
        missing = sorted(set(required_cases) - self.cases.keys())
        if missing:
            raise ProtocolError(
                f"suite {self.suite!r} omitted cases: {', '.join(missing)}")
        observed_passed = sum(case.passed for case in self.cases.values())
        observed_failed = len(self.cases) - observed_passed
        if (self.passed, self.failed) != (observed_passed, observed_failed):
            raise ProtocolError(
                f"suite {self.suite!r} DONE counts "
                f"{self.passed}/{self.failed} do not match cases "
                f"{observed_passed}/{observed_failed}")
        failures = [case for case in self.cases.values() if not case.passed]
        if self.failed != 0 or failures:
            detail = ", ".join(
                f"{case.case_id}(0x{case.code:x}:{case.detail})"
                for case in failures)
            raise ProtocolError(
                f"suite {self.suite!r} reported failures: {detail}")


class ProtocolParser:
    def __init__(self, suite: str):
        self.result = SuiteResult(suite=suite)
        self._line_buffer = ""

    def feed(self, data: bytes | str) -> list[CaseResult]:
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="replace")
        else:
            text = data
        self.result.raw_console += text
        self._line_buffer += text.replace("\r", "")
        new_cases = []
        while "\n" in self._line_buffer:
            line, self._line_buffer = self._line_buffer.split("\n", 1)
            case = self._parse_line(line.strip())
            if case is not None:
                new_cases.append(case)
        return new_cases

    def _parse_line(self, line: str) -> CaseResult | None:
        if not line.startswith("IA64TEST "):
            return None
        match = CASE_RE.fullmatch(line)
        if match:
            if match["suite"] != self.result.suite:
                raise ProtocolError(
                    f"expected suite {self.result.suite!r}, got "
                    f"{match['suite']!r}")
            if self.result.done:
                raise ProtocolError("case appeared after DONE")
            case_id = match["case"]
            if case_id in self.result.cases:
                raise ProtocolError(f"duplicate case ID {case_id!r}")
            passed = match["status"] == "PASS"
            if passed and (match["code"] is not None or
                           match["detail"] is not None):
                raise ProtocolError("PASS line contains failure fields")
            if not passed and (match["code"] is None or
                               match["detail"] is None):
                raise ProtocolError("FAIL line omits code/detail")
            case = CaseResult(
                case_id, passed,
                int(match["code"], 16) if match["code"] else None,
                match["detail"],
            )
            self.result.cases[case_id] = case
            return case

        match = DONE_RE.fullmatch(line)
        if match:
            if match["suite"] != self.result.suite:
                raise ProtocolError(
                    f"expected suite {self.result.suite!r}, got "
                    f"{match['suite']!r}")
            if self.result.done:
                raise ProtocolError("duplicate DONE line")
            self.result.passed = int(match["passed"])
            self.result.failed = int(match["failed"])
            return None
        raise ProtocolError(f"malformed IA64TEST line: {line!r}")


def select_default_boot(console_socket, timeout: float = 60.0,
                        marker: str = "select a boot option") -> None:
    """Trigger a bare-media boot from the wait-forever (0xFFFF) boot menu.

    Real firmware -- and ours -- defaults ``Timeout`` to 0xFFFF, so the boot
    manager waits for a selection instead of auto-booting.  A test that supplies
    bootable media must therefore select the highlighted default option
    ('Removable Media Boot').  Wait for the menu prompt on the serial console,
    then send Enter.
    """
    deadline = time.monotonic() + timeout
    buf = ""
    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        readable, _, _ = select.select(
            [console_socket], [], [], min(0.5, remaining))
        if not readable:
            continue
        data = console_socket.recv(4096)
        if not data:
            raise ProtocolError("console closed before the boot menu appeared")
        buf += data.decode("utf-8", errors="replace")
        if marker in buf:
            console_socket.sendall(b"\r")
            return
    raise ProtocolError(
        f"timed out waiting for the boot menu\n{buf[-2000:]}")


def wait_for_suite(console_socket, suite: str, required_cases: Iterable[str],
                   timeout: float,
                   on_case: Callable[[CaseResult], None] | None = None,
                   process_alive: Callable[[], bool] | None = None
                   ) -> SuiteResult:
    parser = ProtocolParser(suite)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if parser.result.done:
            parser.result.assert_valid(required_cases)
            return parser.result
        if process_alive is not None and not process_alive():
            raise ProtocolError(
                f"QEMU exited before suite {suite!r} completed\n"
                f"{parser.result.raw_console[-4000:]}")
        remaining = max(0.0, deadline - time.monotonic())
        readable, _, _ = select.select(
            [console_socket], [], [], min(0.1, remaining))
        if not readable:
            continue
        data = console_socket.recv(4096)
        if not data:
            raise ProtocolError(
                f"console closed before suite {suite!r} completed")
        for case in parser.feed(data):
            if on_case is not None:
                on_case(case)
    raise ProtocolError(
        f"timed out waiting for suite {suite!r}\n"
        f"{parser.result.raw_console[-4000:]}")
