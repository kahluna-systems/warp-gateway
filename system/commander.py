"""
Safe subprocess command execution wrapper.
Every system command in the gateway goes through this module.
Provides logging, sudo elevation, timeout, and structured results.
"""
import subprocess
import shlex
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("warp.system")


@dataclass
class CommandResult:
    """Structured result from a system command execution."""
    success: bool
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    command: str = ""
    duration_ms: float = 0.0
    error: Optional[str] = None

    def __bool__(self):
        return self.success


def run(
    cmd: list,
    sudo: bool = False,
    timeout: int = 30,
    check: bool = False,
    input_data: Optional[str] = None,
) -> CommandResult:
    """
    Execute a system command safely.

    Args:
        cmd: Command as a list of strings, e.g. ["wg", "show"]
        sudo: Prepend sudo -n (non-interactive) to the command
        timeout: Maximum seconds to wait
        check: If True, raise on non-zero exit (default: return result)
        input_data: String to pass to stdin

    Returns:
        CommandResult with success, stdout, stderr, return_code, timing
    """
    if sudo:
        cmd = ["sudo", "-n"] + cmd

    cmd_str = " ".join(shlex.quote(str(c)) for c in cmd)
    logger.debug(f"Executing: {cmd_str}")

    start = time.monotonic()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
        duration = (time.monotonic() - start) * 1000

        result = CommandResult(
            success=proc.returncode == 0,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
            return_code=proc.returncode,
            command=cmd_str,
            duration_ms=round(duration, 1),
        )

        if result.success:
            logger.debug(f"Success ({result.duration_ms}ms): {cmd_str}")
        else:
            logger.warning(
                f"Failed (rc={result.return_code}, {result.duration_ms}ms): {cmd_str}\n"
                f"  stderr: {result.stderr[:200]}"
            )

        if check and not result.success:
            raise CommandError(result)

        return result

    except subprocess.TimeoutExpired:
        duration = (time.monotonic() - start) * 1000
        logger.error(f"Timeout ({timeout}s): {cmd_str}")
        return CommandResult(
            success=False,
            command=cmd_str,
            duration_ms=round(duration, 1),
            error=f"Command timed out after {timeout}s",
        )

    except FileNotFoundError:
        logger.error(f"Command not found: {cmd[0] if not sudo else cmd[2]}")
        return CommandResult(
            success=False,
            command=cmd_str,
            error=f"Command not found: {cmd[0] if not sudo else cmd[2]}",
        )

    except Exception as e:
        duration = (time.monotonic() - start) * 1000
        logger.error(f"Exception running {cmd_str}: {e}")
        return CommandResult(
            success=False,
            command=cmd_str,
            duration_ms=round(duration, 1),
            error=str(e),
        )


def run_pipe(cmd1: list, cmd2: list, sudo: bool = False, timeout: int = 30) -> CommandResult:
    """
    Execute two commands piped together: cmd1 | cmd2

    Args:
        cmd1: First command (producer)
        cmd2: Second command (consumer)
        sudo: Prepend sudo to cmd1
        timeout: Maximum seconds to wait
    """
    if sudo:
        cmd1 = ["sudo", "-n"] + cmd1

    cmd_str = f"{' '.join(cmd1)} | {' '.join(cmd2)}"
    logger.debug(f"Executing pipe: {cmd_str}")

    start = time.monotonic()

    try:
        p1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = subprocess.Popen(cmd2, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p1.stdout.close()

        stdout, stderr = p2.communicate(timeout=timeout)
        p1.wait(timeout=5)

        duration = (time.monotonic() - start) * 1000

        return CommandResult(
            success=p2.returncode == 0,
            stdout=stdout.decode().strip(),
            stderr=stderr.decode().strip(),
            return_code=p2.returncode,
            command=cmd_str,
            duration_ms=round(duration, 1),
        )

    except Exception as e:
        duration = (time.monotonic() - start) * 1000
        logger.error(f"Pipe execution failed: {cmd_str}: {e}")
        return CommandResult(
            success=False,
            command=cmd_str,
            duration_ms=round(duration, 1),
            error=str(e),
        )


class CommandError(Exception):
    """Raised when a command fails and check=True."""
    def __init__(self, result: CommandResult):
        self.result = result
        super().__init__(f"Command failed (rc={result.return_code}): {result.command}\n{result.stderr}")


def which(binary: str) -> Optional[str]:
    """Check if a binary exists in PATH. Returns path or None."""
    result = run(["which", binary])
    return result.stdout if result.success else None


def version(binary: str, flag: str = "--version") -> Optional[str]:
    """Get version string of a binary."""
    result = run([binary, flag])
    if result.success:
        return result.stdout.split("\n")[0]
    return None
