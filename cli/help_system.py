"""
Context-aware help system for the CLI shell.
Displays available commands and arguments when the user types "?".
"""
from cli.command_tree import CommandNode, get_command_trees


class HelpSystem:
    """Provides context-aware help for the CLI shell."""

    def __init__(self):
        self._trees = get_command_trees()

    def get_help(self, line: str, current_mode: str) -> str:
        """
        Return help text for the current position in the command line.

        Args:
            line: The input line up to the "?" character.
            current_mode: Current CLI mode.

        Returns:
            Formatted help text showing available commands or arguments.
        """
        tree = self._trees.get(current_mode, {})
        tokens = line.strip().split()

        if not tokens:
            return self._format_commands(tree)

        # Walk the tree to find the current position
        current_children = tree
        for i, token in enumerate(tokens):
            matches = self._prefix_match(token, current_children)

            if len(matches) == 0:
                return '% Unrecognized command'
            elif len(matches) == 1:
                node = matches[0]
                if i == len(tokens) - 1:
                    # Last token -- show children or params
                    if line.endswith(' '):
                        # Token is complete, show next level
                        if node.children:
                            return self._format_commands(node.children)
                        elif node.params:
                            return self._format_params(node.params)
                        else:
                            return '  <cr>'
                    else:
                        # Token is partial, show matching commands at this level
                        partial_matches = {
                            name: n for name, n in current_children.items()
                            if name.lower().startswith(token.lower())
                        }
                        return self._format_commands(partial_matches)
                current_children = node.children
            else:
                # Multiple matches -- show them
                match_dict = {m.name: m for m in matches}
                return self._format_commands(match_dict)

        return self._format_commands(current_children)

    @staticmethod
    def _prefix_match(token: str, candidates: dict) -> list:
        """Find nodes matching a token prefix."""
        token_lower = token.lower()
        for name, node in candidates.items():
            if name.lower() == token_lower:
                return [node]
        return [
            node for name, node in candidates.items()
            if name.lower().startswith(token_lower)
        ]

    @staticmethod
    def _format_commands(commands: dict) -> str:
        """Format a dict of command nodes as help output."""
        if not commands:
            return '  <cr>'

        max_name = max(len(name) for name in commands)
        lines = []
        for name in sorted(commands.keys()):
            node = commands[name]
            lines.append(f'  {name.ljust(max_name)}  {node.help_text}')
        return '\n'.join(lines)

    @staticmethod
    def _format_params(params: list) -> str:
        """Format parameter definitions as help output."""
        if not params:
            return '  <cr>'

        lines = []
        for p in params:
            indicator = '' if p.required else ' (optional)'
            choices_str = f' [{"|".join(p.choices)}]' if p.choices else ''
            lines.append(f'  <{p.name}>{choices_str}  {p.help_text}{indicator}')
        lines.append('  <cr>')
        return '\n'.join(lines)
