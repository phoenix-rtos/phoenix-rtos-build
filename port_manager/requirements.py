#
# Port management
#
# Resolver requirement types
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

from __future__ import annotations
from typing import TYPE_CHECKING
from collections.abc import Iterable

import operator
import sys

from .version import PhxVersion

if TYPE_CHECKING:
    from .candidates import Candidate

Constraint = tuple[str, PhxVersion]
"""e.g. (">=", PhxVersion("3.0"))"""


class Requirement:
    @property
    def name(self) -> str:
        """The name identifying this requirement in the resolver"""
        raise NotImplementedError("Subclass should override")

    def is_satisfied_by(self, candidate: Candidate) -> bool:
        return False


def constraint_satisfied(candidate_version: PhxVersion, constraint: Constraint) -> bool:
    relation, constraint_version = constraint
    match relation:
        case ">=":
            op = operator.ge
        case "<=":
            op = operator.le
        case "==":
            op = operator.eq
        case ">":
            op = operator.gt
        case "<":
            op = operator.lt
        case "!=":
            op = operator.ne
        case _:
            sys.exit(f"invalid/unsupported relation: '{relation}'")
    return op(candidate_version, constraint_version)


class BaseRequirement(Requirement):
    """Expresses requirement for given dependency versions, e.g. that version of
    A must be >=1.0 and <=3.0

    Optionally carries propagated_use_flags: USE flags to enable on the
    dependency candidate when it is installed."""

    def __init__(self, name: str, constraints: Iterable[Constraint],
                 propagated_use_flags: list[str] | None = None) -> None:
        self._name = name
        self.constraints = constraints
        self.propagated_use_flags = propagated_use_flags or []

    def __repr__(self) -> str:
        base = self._name + ",".join(
            [rel + str(ver) for (rel, ver) in self.constraints]
        )
        if self.propagated_use_flags:
            return f"{base}[{','.join(self.propagated_use_flags)}]"
        return base

    @property
    def name(self) -> str:
        return self._name

    def is_satisfied_by(self, candidate: Candidate) -> bool:
        for constraint in self.constraints:
            if not constraint_satisfied(candidate.version, constraint):
                return False
        return True


class ConflictRequirement(BaseRequirement):
    """Expresses conflict with given package version, e.g. that it conflicts with
    A in versions >=1.0 and <=3.0 (a negation of BaseRequirement)"""

    def __init__(self, name: str, cname: str, constraints: Iterable[Constraint]) -> None:
        super().__init__(name, constraints)
        self._cname = cname

    def __repr__(self) -> str:
        return "[!]" + self.cname

    @property
    def cname(self) -> str:
        return self._cname

    def is_satisfied_by(self, candidate: Candidate) -> bool:
        """
        Checks if a candidate is compatible with this conflict requirement.

        NOTE: This is a negation of the parent's method. It returns True if
        the candidate does NOT fall into the conflicting version range.
        """
        return not super().is_satisfied_by(candidate)


class ConditionalRequirement(BaseRequirement):
    """A requirement that is only active when a specific USE flag is enabled
    on the parent candidate."""

    def __init__(self, name: str, constraints: Iterable[Constraint], use_flag: str,
                 propagated_use_flags: list[str] | None = None) -> None:
        super().__init__(name, constraints, propagated_use_flags)
        self.use_flag = use_flag

    def __repr__(self) -> str:
        return f"{self.use_flag}? ({super().__repr__()})"
