"""
Per-session candidate configuration for configure private mode.
Holds a snapshot of the running config and accumulates commands
until the operator commits or discards.
"""
import difflib


class CandidateConfig:
    """
    Per-session isolated configuration for configure private mode.
    """

    def __init__(self, baseline_text: str):
        self._baseline = str(baseline_text)
        self._commands = []

    @property
    def baseline(self) -> str:
        return self._baseline

    @property
    def commands(self) -> list:
        return list(self._commands)

    def record_command(self, command: str) -> None:
        self._commands.append(command)

    def get_modified_text(self, serializer) -> str:
        """
        Apply recorded commands to produce new config text.
        In practice, the commands have already been applied to the database
        during the private session. This serializes the current DB state.
        """
        return serializer.serialize_running_config()

    def diff(self, current_running: str) -> str:
        """Return a unified diff between the baseline and current running config."""
        baseline_lines = self._baseline.splitlines(keepends=True)
        current_lines = current_running.splitlines(keepends=True)

        diff_lines = difflib.unified_diff(
            baseline_lines,
            current_lines,
            fromfile='baseline',
            tofile='running',
            lineterm='',
        )
        return '\n'.join(diff_lines)
