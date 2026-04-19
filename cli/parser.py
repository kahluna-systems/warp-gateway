"""
Command tokenizer and abbreviation resolver.
Parses user input against the command tree and dispatches to handlers.
"""
from dataclasses import dataclass, field
from typing import Optional

from cli.command_tree import CommandNode, get_command_trees


@dataclass
class ParseResult:
    """Result of parsing a command line."""
    resolved_node: Optional[CommandNode] = None
    args: list = field(default_factory=list)
    error: Optional[str] = None  # 'ambiguous', 'unknown', 'incomplete'
    matches: list = field(default_factory=list)  # For ambiguous case
    path: list = field(default_factory=list)  # Resolved command path (e.g., ['show', 'interfaces'])


class CommandParser:
    """Tokenizes input and resolves against the command tree."""

    def __init__(self):
        self._trees = get_command_trees()

    def parse(self, line: str, current_mode: str) -> ParseResult:
        """
        Parse a command line into a resolved command and arguments.

        Args:
            line: Raw user input string
            current_mode: Current CLI mode (exec, privileged, configure, etc.)

        Returns:
            ParseResult with resolved node, args, or error info.
        """
        tokens = line.strip().split()
        if not tokens:
            return ParseResult()

        tree = self._trees.get(current_mode, {})
        return self._walk_tree(tokens, tree)

    def _walk_tree(self, tokens: list, tree: dict) -> ParseResult:
        """Walk the command tree matching tokens to nodes."""
        current_children = tree
        path = []
        node = None

        for i, token in enumerate(tokens):
            matches = self.resolve_abbreviation(token, current_children)

            if len(matches) == 0:
                # If we already resolved a node and this token doesn't match a child,
                # treat remaining tokens as arguments
                if node is not None:
                    return ParseResult(
                        resolved_node=node,
                        args=tokens[i:],
                        path=path,
                    )
                return ParseResult(
                    error='unknown',
                    args=tokens,
                )

            if len(matches) == 1:
                node = matches[0]
                path.append(node.name)
                current_children = node.children
            else:
                return ParseResult(
                    error='ambiguous',
                    matches=matches,
                    args=tokens[i:],
                    path=path,
                )

        # Reached end of tokens
        if node is not None:
            return ParseResult(resolved_node=node, path=path)
        return ParseResult(error='unknown', args=tokens)

    @staticmethod
    def resolve_abbreviation(token: str, candidates: dict) -> list:
        """
        Resolve a possibly abbreviated token against candidate command names.

        Args:
            token: User-typed token (possibly abbreviated)
            candidates: Dict of command_name -> CommandNode

        Returns:
            List of matching CommandNode objects.
        """
        token_lower = token.lower()

        # Exact match first
        if token_lower in {k.lower() for k in candidates}:
            for name, node in candidates.items():
                if name.lower() == token_lower:
                    return [node]

        # Prefix match
        matches = []
        for name, node in candidates.items():
            if name.lower().startswith(token_lower):
                matches.append(node)

        return matches
