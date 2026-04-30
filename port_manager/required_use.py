#
# Port management
#
# REQUIRED_USE constraint parser and validator
#
# Implements Gentoo-like REQUIRED_USE semantics for USE flag constraints.
# See: https://devmanual.gentoo.org/ebuild-writing/variables/index.html#required_use
#
# Supported syntax:
#   ^^ ( a b c )     - exactly one of a, b, c must be enabled
#   ?? ( a b c )     - at most one of a, b, c may be enabled
#   || ( a b c )     - at least one of a, b, c must be enabled
#   flag? ( b c )    - if flag is enabled, b and c must be enabled
#   !flag? ( b )     - if flag is disabled, b must be enabled
#   flag? ( !b )     - if flag is enabled, b must be disabled
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

from __future__ import annotations
from dataclasses import dataclass

import pyparsing as pp


@dataclass
class RequiredUseExpr:
    """Base class for REQUIRED_USE constraint expressions"""
    pass


@dataclass
class ExactlyOneOf(RequiredUseExpr):
    """^^ ( flag1 flag2 ... ) - exactly one must be enabled"""
    flags: list[str]

    def __str__(self) -> str:
        return f"^^ ( {' '.join(self.flags)} )"


@dataclass
class AtMostOneOf(RequiredUseExpr):
    """?? ( flag1 flag2 ... ) - zero or one may be enabled"""
    flags: list[str]

    def __str__(self) -> str:
        return f"?? ( {' '.join(self.flags)} )"


@dataclass
class AnyOf(RequiredUseExpr):
    """|| ( flag1 flag2 ... ) - at least one must be enabled"""
    flags: list[str]

    def __str__(self) -> str:
        return f"|| ( {' '.join(self.flags)} )"


@dataclass
class Conditional(RequiredUseExpr):
    """flag? ( required... ) or !flag? ( required... )
    Children may be negated with ! prefix: flag? ( !other ) means
    'if flag is enabled, other must be disabled'."""
    flag: str
    negated: bool
    children: list[str]

    def __str__(self) -> str:
        prefix = "!" if self.negated else ""
        return f"{prefix}{self.flag}? ( {' '.join(self.children)} )"


class RequiredUseGrammar:
    """
    Grammar for parsing REQUIRED_USE constraint strings.

    Examples:
        >>> RequiredUseGrammar.parse_string("^^ ( a b c )")
        [ExactlyOneOf(flags=['a', 'b', 'c'])]

        >>> RequiredUseGrammar.parse_string("?? ( x1 x2 )")
        [AtMostOneOf(flags=['x1', 'x2'])]

        >>> RequiredUseGrammar.parse_string("ssl? ( crypto )")
        [Conditional(flag='ssl', negated=False, children=['crypto'])]

        >>> RequiredUseGrammar.parse_string("!minimal? ( extras )")
        [Conditional(flag='minimal', negated=True, children=['extras'])]

        >>> RequiredUseGrammar.parse_string("ssl? ( !gnutls )")
        [Conditional(flag='ssl', negated=False, children=['!gnutls'])]
    """

    flag = pp.Word(pp.alphanums + "_")
    neg_flag = pp.Combine(pp.Literal("!") + flag)
    flag_item = neg_flag | flag

    group_op = pp.one_of("^^ ?? ||")
    group_expr = pp.Group(
        group_op("op")
        + pp.Suppress("(")
        + pp.Group(pp.OneOrMore(flag))("flags")
        + pp.Suppress(")")
    )

    cond_flag = pp.Combine(pp.Optional("!") + flag + pp.FollowedBy("?"))
    cond_expr = pp.Group(
        cond_flag("cond_flag")
        + pp.Suppress("?")
        + pp.Suppress("(")
        + pp.Group(pp.OneOrMore(flag_item))("children")
        + pp.Suppress(")")
    )

    expr = cond_expr | group_expr
    grammar = pp.ZeroOrMore(expr)

    @staticmethod
    def _to_expr(parsed: pp.ParseResults) -> RequiredUseExpr:
        if "op" in parsed:
            flags = list(parsed["flags"])
            op = parsed["op"]
            cls = {"^^": ExactlyOneOf, "??": AtMostOneOf, "||": AnyOf}[op]
            return cls(flags)
        else:
            raw = parsed["cond_flag"]
            negated = raw.startswith("!")
            flag = raw.lstrip("!")
            children = list(parsed["children"])
            return Conditional(flag, negated, children)

    @staticmethod
    def parse_string(s: str) -> list[RequiredUseExpr]:
        result = RequiredUseGrammar.grammar.parse_string(s, parse_all=True)
        return [RequiredUseGrammar._to_expr(item) for item in result]


def parse_required_use(s: str) -> list[RequiredUseExpr]:
    """Parse a REQUIRED_USE string into a list of constraint expressions."""
    if not s or not s.strip():
        return []
    return RequiredUseGrammar.parse_string(s)


def validate_required_use(
    exprs: list[RequiredUseExpr], active_flags: set[str]
) -> tuple[bool, str]:
    """Check whether active_flags satisfy all REQUIRED_USE constraints.

    Returns (is_valid, error_message). error_message is empty when valid.
    """
    for expr in exprs:
        if isinstance(expr, ExactlyOneOf):
            active = [f for f in expr.flags if f in active_flags]
            if len(active) != 1:
                return (
                    False,
                    f"exactly one of ({', '.join(expr.flags)}) required, "
                    f"but {len(active)} enabled"
                    + (f": {', '.join(active)}" if active else ""),
                )

        elif isinstance(expr, AtMostOneOf):
            active = [f for f in expr.flags if f in active_flags]
            if len(active) > 1:
                return (
                    False,
                    f"at most one of ({', '.join(expr.flags)}) allowed, "
                    f"but {len(active)} enabled: {', '.join(active)}",
                )

        elif isinstance(expr, AnyOf):
            active = [f for f in expr.flags if f in active_flags]
            if len(active) == 0:
                return (
                    False,
                    f"at least one of ({', '.join(expr.flags)}) required",
                )

        elif isinstance(expr, Conditional):
            condition_met = (
                (expr.flag not in active_flags)
                if expr.negated
                else (expr.flag in active_flags)
            )
            if condition_met:
                for child in expr.children:
                    if child.startswith("!"):
                        real_flag = child[1:]
                        if real_flag in active_flags:
                            return (
                                False,
                                f"{expr} violated: "
                                f"{real_flag} must be disabled",
                            )
                    else:
                        if child not in active_flags:
                            return (
                                False,
                                f"{expr} violated: "
                                f"{child} must be enabled",
                            )

    return True, ""
