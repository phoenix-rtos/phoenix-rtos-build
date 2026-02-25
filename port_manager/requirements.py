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
        case _:
            sys.exit(f"invalid/unsupported relation: '{relation}'")
    return op(candidate_version, constraint_version)


class BaseRequirement(Requirement):
    """Expresses requirement for given dependency versions, e.g. that version of
    A must be >=1.0 and <=3.0"""

    def __init__(self, name: str, constraints: Iterable[Constraint]) -> None:
        self._name = name
        self.constraints = constraints

    def __repr__(self) -> str:
        return self._name + ",".join(
            [rel + str(ver) for (rel, ver) in self.constraints]
        )

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
        return self._cname != candidate.name


class OptionalRequirement(BaseRequirement):
    """Expresses optional requirement for given dependency versions. Can be
    dropped by the resolver if unsatisfiable"""

    def __repr__(self) -> str:
        return "[o]" + super().__repr__()
