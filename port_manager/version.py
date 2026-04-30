#
# Port management
#
# Version class and parsing grammar
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

from __future__ import annotations

# NOTE: We use Python Version Specifiers for parsing port version strings:
# https://packaging.python.org/en/latest/specifications/version-specifiers/
# For now, the scheme seems flexible enough to express our versioning
# requirements.
from packaging.version import Version

import pyparsing as pp


class PhxVersion(Version):
    def __str__(self) -> str:
        """
        A modified Version.__str__ that does not print added zeros in
        pre-release, so that '1.1.1a' is printed as '1.1.1a', not as '1.1.1a0'
        """
        parts = []

        # Epoch
        if self.epoch != 0:
            parts.append(f"{self.epoch}!")

        # Release segment
        parts.append(".".join(str(x) for x in self.release))

        # Pre-release
        if self.pre is not None and len(self.pre) > 1:
            parts.append("".join(str(x) for x in self.pre[:-1]))

        # Post-release
        if self.post is not None:
            parts.append(f".post{self.post}")

        # Development release
        if self.dev is not None:
            parts.append(f".dev{self.dev}")

        # Local self segment
        if self.local is not None:
            parts.append(f"+{self.local}")

        return "".join(parts)


class PhxVersionGrammar:
    """
    Grammar for parsing dependency requirement strings.

    Examples:
        >>> PhxVersionGrammar.parse_string("foo>=1.1 bar<2.0").as_list()
        [['foo', '>=', <Version('1.1')>], ['bar', '<', <Version('2.0')>]]

        >>> PhxVersionGrammar.parse_string("foo>3").as_list()
        [['foo', '>', <Version('3')>]]

        >>> PhxVersionGrammar.parse_string("foo ? (foo >=1.1) bar==3").as_list()
        [['foo', [['foo', '>=', <Version('1.1')>]]], ['bar', '==', <Version('3')>]]
    """

    package = pp.Word(pp.alphanums + "_")
    version = (
        pp.Regex(r"\b\d+(?:(?:\.\d+){1,2})?[a-z]?\b")
        .set_name("version")
        .set_parse_action(pp.token_map(PhxVersion))
    )
    no_version_op = pp.Empty().set_parse_action(lambda: ">=")
    no_version = (
        pp.Empty().set_name("version").set_parse_action(lambda: PhxVersion("0.0"))
    )
    version_op = pp.one_of(">= <= == > < !=")

    # USE flag propagation: dep>=ver[flag1,flag2]
    use_flag = pp.Word(pp.alphanums + "_")
    use_flags = pp.Suppress("[") + pp.delimited_list(use_flag) + pp.Suppress("]")
    opt_use_flags = pp.Group(use_flags)("use_flags") | pp.Empty().set_parse_action(lambda: [])("use_flags")

    # Base dependency expression (with optional USE flags)
    dep_with_ver = pp.Group(package + version_op + version + opt_use_flags)
    dep_without_ver = pp.Group(package + no_version_op + no_version + opt_use_flags)
    dep_expr = dep_with_ver ^ dep_without_ver

    # Conditional dependency: flag ? ( dep_expr ... )
    cond_flag = pp.Word(pp.alphanums + "_")
    cond_expr = pp.Group(
        cond_flag("cond_flag") + pp.Suppress("?") + pp.Suppress("(") +
        pp.Group(pp.OneOrMore(dep_expr))("cond_deps") +
        pp.Suppress(")")
    )

    e0 = pp.ZeroOrMore(cond_expr("conditional*") | dep_expr)

    @staticmethod
    def parse_string(s: str) -> pp.ParseResults:
        """Parse a requirement string.

        Returns a pyparsing.ParseResults object. Each element is either:
        - [name, op, version, use_flags] for unconditional deps
        - Has 'cond_flag' and 'cond_deps' attributes for conditional deps where
          each dep from cond_deps has a structure like the uncoditional dep
          element.
        """
        return PhxVersionGrammar.e0.parse_string(s)
