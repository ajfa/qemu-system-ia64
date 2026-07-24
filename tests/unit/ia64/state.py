"""Parser and typed expectations for machine-readable IA-64 CPU state."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import re
from types import MappingProxyType


class StateParseError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExpectedFP:
    low: int
    high: int
    nat: bool = False


@dataclass(frozen=True)
class ExpectedBits:
    mask: int
    value: int

    def matches(self, actual: int) -> bool:
        return actual & self.mask == self.value & self.mask


@dataclass(frozen=True)
class FPState:
    low: int
    high: int
    nat: bool


ExpectedValue = int | ExpectedBits | ExpectedFP


@dataclass(frozen=True)
class StateExpectation:
    """Typed architectural values required at a program's terminal state."""

    values: Mapping[str, ExpectedValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # A frozen dataclass containing a caller-owned dict is not actually
        # immutable.  Snapshot it so a registered test cannot change while it
        # is running (or between --repeat iterations).
        object.__setattr__(self, "values",
                           MappingProxyType(dict(self.values)))

    @property
    def ip(self) -> int | None:
        value = self.values.get("ip")
        return value if isinstance(value, int) else None

    def mismatches(self, state: "Ia64State") -> list[str]:
        failures: list[str] = []
        for name, wanted in self.values.items():
            if isinstance(wanted, ExpectedFP):
                if not name.startswith("f") or not name[1:].isdigit():
                    raise StateParseError(
                        f"FP expectation has invalid key {name!r}")
                actual = state.fr.get(int(name[1:]))
                observed = None if actual is None else (
                    actual.low, actual.high, actual.nat)
                required = (wanted.low, wanted.high, wanted.nat)
                if observed != required:
                    failures.append(
                        f"{name}: expected {required!r}, got {observed!r}")
            elif isinstance(wanted, ExpectedBits):
                actual = state.value(name)
                if actual is None or not wanted.matches(actual):
                    failures.append(
                        f"{name}: expected mask=0x{wanted.mask:x} "
                        f"value=0x{wanted.value:x}, got {actual!r}")
            else:
                actual = state.value(name)
                if actual != wanted:
                    failures.append(
                        f"{name}: expected 0x{wanted:x}, got {actual!r}")
        return failures

    def matches(self, state: "Ia64State") -> bool:
        return not self.mismatches(state)


@dataclass
class Ia64State:
    ip: int | None = None
    psr: int | None = None
    halted: bool | None = None
    exception: int | None = None
    fault_code: int | None = None
    fault_ip: int | None = None
    fault_imm: int | None = None
    gr_nat_lo: int | None = None
    gr_nat_hi: int | None = None
    pr_mask: int | None = None
    gr: dict[int, int] = field(default_factory=dict)
    gr_nat: dict[int, bool] = field(default_factory=dict)
    br: dict[int, int] = field(default_factory=dict)
    ar: dict[str, int] = field(default_factory=dict)
    cfm: dict[str, int] = field(default_factory=dict)
    fr: dict[int, FPState] = field(default_factory=dict)

    def value(self, name: str) -> int | None:
        """Return one scalar architectural field by its typed expectation key."""
        scalar = {
            "ip": self.ip,
            "psr": self.psr,
            "halted": None if self.halted is None else int(self.halted),
            "exception": self.exception,
            "fault_code": self.fault_code,
            "fault_ip": self.fault_ip,
            "fault_imm": self.fault_imm,
            "pr_mask": self.pr_mask,
            "gr_nat_lo": self.gr_nat_lo,
            "gr_nat_hi": self.gr_nat_hi,
        }
        if name in scalar:
            return scalar[name]

        match = re.fullmatch(r"r(\d+)(_nat)?", name)
        if match is not None:
            index = int(match.group(1))
            if index >= 128:
                raise StateParseError(f"invalid GR expectation key {name!r}")
            if match.group(2):
                nat = self.gr_nat.get(index)
                return None if nat is None else int(nat)
            return self.gr.get(index)

        match = re.fullmatch(r"b(\d+)", name)
        if match is not None:
            index = int(match.group(1))
            if index >= 8:
                raise StateParseError(f"invalid BR expectation key {name!r}")
            return self.br.get(index)

        match = re.fullmatch(r"p(\d+)", name)
        if match is not None:
            index = int(match.group(1))
            if index >= 64:
                raise StateParseError(
                    f"invalid predicate expectation key {name!r}")
            return (None if self.pr_mask is None else
                    (self.pr_mask >> index) & 1)

        if name.startswith("ar_"):
            field_name = name.removeprefix("ar_")
            if field_name not in ("ccv", "unat", "fpsr", "csd", "ssd",
                                   "rsc", "rnat", "pfs"):
                raise StateParseError(f"invalid AR expectation key {name!r}")
            return self.ar.get(field_name)

        if name.startswith("cfm_"):
            field_name = name.removeprefix("cfm_")
            if field_name not in ("sof", "sol", "sor", "rrb_gr", "rrb_fr",
                                   "rrb_pr"):
                raise StateParseError(f"invalid CFM expectation key {name!r}")
            return self.cfm.get(field_name)

        raise StateParseError(f"unknown scalar expectation key {name!r}")


_LINE = re.compile(r"^IA64STATE\s+(\S+)(?:\s+(.*))?$")
_FIELD = re.compile(r"([a-z_]+)=([0-9a-f]+)")


def _fields(text: str) -> dict[str, int]:
    result = {}
    for token in text.split():
        match = _FIELD.fullmatch(token)
        if match is None:
            raise StateParseError(
                f"malformed IA64STATE field: {token!r}")
        name, value = match.groups()
        if name in result:
            raise StateParseError(f"duplicate IA64STATE field {name!r}")
        result[name] = int(value, 16)
    if not result:
        raise StateParseError(f"malformed IA64STATE line: {text!r}")
    return result


def _required(values: dict[str, int], names: tuple[str, ...], kind: str) -> None:
    missing = [name for name in names if name not in values]
    if missing:
        raise StateParseError(f"{kind} line lacks fields: {', '.join(missing)}")
    unexpected = sorted(set(values) - set(names))
    if unexpected:
        raise StateParseError(
            f"{kind} line has unexpected fields: {', '.join(unexpected)}")


def parse_state(output: str, *, require_fpu: bool = True) -> Ia64State:
    state = Ia64State()
    seen: set[str] = set()

    for raw_line in output.splitlines():
        match = _LINE.match(raw_line.strip())
        if match is None:
            continue
        kind, rest = match.groups()
        values = _fields(rest or "")

        if kind == "SCHEMA":
            if kind in seen:
                raise StateParseError(f"duplicate IA64STATE {kind} record")
            _required(values, ("version",), kind)
            if values["version"] != 1:
                raise StateParseError(
                    f"unsupported IA64STATE schema version "
                    f"{values['version']}")
            seen.add(kind)
        elif kind == "META":
            if kind in seen:
                raise StateParseError(f"duplicate IA64STATE {kind} record")
            _required(values, ("ip", "psr", "halted"), kind)
            if values["halted"] not in (0, 1):
                raise StateParseError("META halted must be zero or one")
            state.ip = values["ip"]
            state.psr = values["psr"]
            state.halted = bool(values["halted"])
            seen.add(kind)
        elif kind == "EXCEPTION":
            if kind in seen:
                raise StateParseError(f"duplicate IA64STATE {kind} record")
            _required(values,
                      ("code", "fault_code", "fault_ip", "fault_imm"),
                      kind)
            state.exception = values["code"]
            state.fault_code = values["fault_code"]
            state.fault_ip = values["fault_ip"]
            state.fault_imm = values["fault_imm"]
            seen.add(kind)
        elif kind == "GRNAT":
            if kind in seen:
                raise StateParseError(f"duplicate IA64STATE {kind} record")
            _required(values, ("lo", "hi"), kind)
            state.gr_nat_lo = values["lo"]
            state.gr_nat_hi = values["hi"]
            seen.add(kind)
        elif kind == "GR":
            _required(values, ("index", "value", "nat"), kind)
            index = values["index"]
            if index in state.gr or index >= 128:
                raise StateParseError(f"duplicate or invalid GR index {index}")
            if values["nat"] not in (0, 1):
                raise StateParseError(f"GR {index} nat must be zero or one")
            state.gr[index] = values["value"]
            state.gr_nat[index] = bool(values["nat"])
        elif kind == "BR":
            _required(values, ("index", "value"), kind)
            index = values["index"]
            if index in state.br or index >= 8:
                raise StateParseError(f"duplicate or invalid BR index {index}")
            state.br[index] = values["value"]
        elif kind == "PR":
            if kind in seen:
                raise StateParseError(f"duplicate IA64STATE {kind} record")
            _required(values, ("value",), kind)
            state.pr_mask = values["value"]
            seen.add(kind)
        elif kind == "AR":
            if kind in seen:
                raise StateParseError(f"duplicate IA64STATE {kind} record")
            required = ("ccv", "unat", "fpsr", "csd", "ssd", "rsc",
                        "rnat", "pfs")
            _required(values, required, kind)
            state.ar = {name: values[name] for name in required}
            seen.add(kind)
        elif kind == "CFM":
            if kind in seen:
                raise StateParseError(f"duplicate IA64STATE {kind} record")
            required = ("sof", "sol", "sor", "rrb_gr", "rrb_fr", "rrb_pr")
            _required(values, required, kind)
            state.cfm = {name: values[name] for name in required}
            seen.add(kind)
        elif kind == "FR":
            _required(values, ("index", "low", "high", "nat"), kind)
            index = values["index"]
            if index in state.fr or index >= 128:
                raise StateParseError(f"duplicate or invalid FR index {index}")
            if values["nat"] not in (0, 1):
                raise StateParseError(f"FR {index} nat must be zero or one")
            state.fr[index] = FPState(values["low"], values["high"],
                                      bool(values["nat"]))
        else:
            raise StateParseError(f"unknown IA64STATE record {kind!r}")

    missing_kinds = sorted({"META", "EXCEPTION", "GRNAT", "PR", "AR", "CFM"}
                           - seen)
    if missing_kinds:
        raise StateParseError("missing IA64STATE records: " +
                              ", ".join(missing_kinds))
    if len(state.gr) != 128:
        raise StateParseError(f"expected 128 GR records, got {len(state.gr)}")
    if len(state.br) != 8:
        raise StateParseError(f"expected 8 BR records, got {len(state.br)}")
    if require_fpu and len(state.fr) != 128:
        raise StateParseError(f"expected 128 FR records, got {len(state.fr)}")
    if not require_fpu and state.fr and len(state.fr) != 128:
        raise StateParseError(f"partial FR record set ({len(state.fr)})")
    return state
