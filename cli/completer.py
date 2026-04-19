"""
Tab completion engine for the CLI shell.
Provides context-aware completion by inspecting the command tree.
"""
from cli.command_tree import CommandNode, get_command_trees


class TabCompleter:
    """Provides tab completion for the CLI shell."""

    def __init__(self):
        self._trees = get_command_trees()

    def complete(self, text: str, line: str, current_mode: str) -> list:
        """
        Return matching completions for the current input.

        Args:
            text: The current token being completed.
            line: The full input line so far.
            current_mode: Current CLI mode.

        Returns:
            List of matching completion strings.
        """
        tree = self._trees.get(current_mode, {})
        tokens = line.strip().split()

        # If the line ends with a space, we're completing a new token
        completing_new = line.endswith(' ') if line else True

        if completing_new:
            # Walk to the current position in the tree
            current_children = tree
            for token in tokens:
                matches = self._prefix_match(token, current_children)
                if len(matches) == 1:
                    current_children = matches[0].children
                else:
                    return []

            # Return all children at this level
            return sorted(current_children.keys())
        else:
            # Complete the last token
            partial = tokens[-1] if tokens else ''
            preceding = tokens[:-1]

            # Walk to the parent position
            current_children = tree
            for token in preceding:
                matches = self._prefix_match(token, current_children)
                if len(matches) == 1:
                    current_children = matches[0].children
                else:
                    return []

            # Find matches for the partial token
            return sorted(
                name for name in current_children
                if name.lower().startswith(partial.lower())
            )

    @staticmethod
    def _prefix_match(token: str, candidates: dict) -> list:
        """Find nodes matching a token prefix."""
        token_lower = token.lower()

        # Exact match
        for name, node in candidates.items():
            if name.lower() == token_lower:
                return [node]

        # Prefix match
        return [
            node for name, node in candidates.items()
            if name.lower().startswith(token_lower)
        ]
