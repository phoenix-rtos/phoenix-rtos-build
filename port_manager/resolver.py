#
# Port management
#
# Dependency resolver
#
# Uses Python's resolvelib backtracking library:
# https://pip.pypa.io/en/stable/topics/more-dependency-resolution/
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

from __future__ import annotations
from typing import (
    Any,
    Protocol,
    TypeVar,
)
from collections.abc import Callable
from collections.abc import Mapping, Iterator, Sequence, Iterable

import resolvelib

from packaging.version import Version
from functools import cache, cmp_to_key

from resolvelib.resolvers import Result

from .logger import logger
from .candidates import Candidate
from .requirements import Requirement, BaseRequirement, OptionalRequirement
from .version import PhxVersion

if Version(resolvelib.__version__) >= Version("1.1.1"):
    from resolvelib.structs import RequirementInformation, State, KT, RT, CT
    from resolvelib.resolvers.criterion import Criterion
else:
    # TODO: Drop the else once python3-resolvelib gets updated to >=1.1.1 on LTS
    # (24.04 LTS has 1.0.1)

    from typing import TYPE_CHECKING, Generic, NamedTuple, Union
    from collections import namedtuple

    KT = TypeVar("KT")  # Identifier.
    RT = TypeVar("RT")  # Requirement.
    CT = TypeVar("CT")  # Candidate.

    Matches = Union[Iterable[CT], Callable[[], Iterable[CT]]]

    if TYPE_CHECKING:

        class RequirementInformation(NamedTuple, Generic[RT, CT]):
            requirement: RT
            parent: CT | None

        class State(NamedTuple, Generic[RT, CT, KT]):
            """Resolution state in a round."""

            mapping: dict[KT, CT]
            criteria: dict[KT, Criterion[RT, CT]]
            backtrack_causes: list[RequirementInformation[RT, CT]]

    else:
        RequirementInformation = namedtuple(
            "RequirementInformation", ["requirement", "parent"]
        )
        State = namedtuple("State", ["mapping", "criteria", "backtrack_causes"])


PreferenceInformation = RequirementInformation[Requirement, Candidate]


class Preference(Protocol):
    def __lt__(self, __other: Any) -> bool: ...


CandidatesDict = dict[str, dict[str, Candidate]]


class PhxProvider(resolvelib.AbstractProvider):
    def __init__(self, all_candidates: CandidatesDict) -> None:
        self.all_candidates = all_candidates
        self.masked_requirements: set[OptionalRequirement] = set()

    def identify(self, requirement_or_candidate: Requirement | Candidate) -> str:
        return requirement_or_candidate.name

    def mask_optional(self, req: OptionalRequirement) -> None:
        logger.debug("masking the optional", req)
        self.masked_requirements.add(req)

    def narrow_requirement_selection(
        self,
        identifiers: Iterable[str],
        resolutions: Mapping[str, Candidate],
        candidates: Mapping[str, Iterator[Candidate]],
        information: Mapping[str, Iterator[PreferenceInformation]],
        backtrack_causes: Sequence[PreferenceInformation],
    ) -> Iterable[str]:
        # TODO: when performance becomes a problem, narrow selections to speed up the resolution
        return identifiers

    def get_preference(
        self,
        identifier: str,
        resolutions: Mapping[str, Candidate],
        candidates: Mapping[str, Iterator[Candidate]],
        information: Mapping[str, Iterable[PreferenceInformation]],
        backtrack_causes: Sequence[PreferenceInformation],
    ) -> Preference:
        # TODO: when performance becomes a problem, add preferences to speed up the resolution
        return 0

    def find_matches(
        self,
        identifier: str,
        requirements: Mapping[str, Iterator[Requirement]],
        incompatibilities: Mapping[str, Iterator[Candidate]],
    ) -> Iterable[Candidate]:
        """Find all possible candidates that satisfy all requirements and are
        not included in incompatibilities.

        Returned iterable is ordered by preference. In our case newer version
        comes first.
        """
        if identifier not in self.all_candidates:
            return []

        logger.debug("find_matches", identifier, requirements)

        res: list[Candidate] = []
        for candidate in self.all_candidates[identifier].values():
            logger.debug(candidate, "requirements:", candidate.iter_dependencies())

            if candidate in incompatibilities.values():
                continue
            good = True
            logger.debug(candidate, "conflict list:", candidate.iter_conflicts())
            for conflict in candidate.iter_conflicts():
                if conflict.cname in requirements:
                    logger.debug(
                        candidate,
                        "conflicts with",
                        conflict.cname,
                        "but it is in requirements",
                    )
                    good = False
                    break
            for requirement in requirements[identifier]:
                if not requirement.is_satisfied_by(candidate):
                    logger.debug(candidate, "doesn't satisfy", requirement)
                    good = False
                    break
                if good:
                    logger.debug(candidate, "satisfies", requirement)
                    res.append(candidate)

        logger.debug("resulting matches", res)

        def cmp_cands(a: Candidate, b: Candidate):
            def cmp(a: PhxVersion, b: PhxVersion):
                return (a > b) - (a < b)

            return -cmp(a.version, b.version)

        # Sort newer versions first
        return sorted(res, key=cmp_to_key(cmp_cands))

    @staticmethod
    @cache
    def is_satisfied_by(requirement: Requirement, candidate: Candidate) -> bool:
        return requirement.is_satisfied_by(candidate)

    def get_dependencies(self, candidate: Candidate) -> Iterable[Requirement]:
        return (
            r
            for r in candidate.iter_dependencies()
            if r is not None
            if r not in self.masked_requirements
        )


class MyReporter(resolvelib.BaseReporter):
    _redo = False

    def __init__(self, provider) -> None:
        self.provider = provider

    def redo_with_masked_optional(self) -> bool:
        res = self._redo
        self._redo = False
        return res

    def ending(self, state: State[RT, CT, KT]) -> None:
        logger.debug("ending", state)

    def adding_requirement(self, requirement: RT, parent: CT | None) -> None:
        logger.debug("adding a requirement:", requirement, "parent:", parent)

    def rejecting_candidate(self, criterion: Criterion[RT, CT], candidate: CT) -> None:
        for req_info in criterion.information:
            req, parent = req_info.requirement, req_info.parent
            if isinstance(req, OptionalRequirement):
                logger.debug(
                    f"{parent} optional requirement for {req} unsatisfiable, dropping"
                )
                self._redo = True
                self.provider.mask_optional(req)
            else:
                logger.debug(f"{parent} requirement for {req} unsatisfiable")


class PhxResolver:
    def __init__(self, all_candidates: CandidatesDict) -> None:
        self.provider = PhxProvider(all_candidates)
        self.reporter = MyReporter(self.provider)
        self.resolver = resolvelib.Resolver(self.provider, self.reporter)

    def resolve(self, reqs: list[BaseRequirement]) -> Result[BaseRequirement, Candidate, KT]:
        while True:
            try:
                return self.resolver.resolve(reqs)
            except resolvelib.resolvers.ResolutionTooDeep as e:
                logger.error(
                    f"Requirements unsatisfiable despite {e.round_count} attempts"
                )
                # NOTE: rethrow resolution exceptions instead of sys.exit(1)
                # to catch exact resolution failures in resolver tests
                raise
            except resolvelib.resolvers.ResolutionImpossible as e:
                causes_strs = []
                for cause in e.causes:
                    causes_strs.append(
                        f"-> {cause.requirement} required by {cause.parent}"
                    )
                logger.error("Requirements unsatisfiable:\n" + "\n".join(causes_strs))
                if self.reporter.redo_with_masked_optional():
                    logger.debug("Redoing resolution with masked optional")
                else:
                    raise
