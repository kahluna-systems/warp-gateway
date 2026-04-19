"""
CLI mode definitions and mode stack management.
Implements the Cisco IOS-style mode hierarchy:
  exec > privileged > configure > sub-modes (if, fw, vpn, dhcp, dns)
"""


# ── Mode Constants ───────────────────────────────────────────────────────────

EXEC = 'exec'
PRIVILEGED = 'privileged'
CONFIGURE = 'configure'
CONFIG_IF = 'config-if'
CONFIG_FW = 'config-fw'
CONFIG_VPN = 'config-vpn'
CONFIG_DHCP = 'config-dhcp'
CONFIG_DNS = 'config-dns'

# All valid modes
ALL_MODES = {EXEC, PRIVILEGED, CONFIGURE, CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS}

# Sub-configuration modes (children of CONFIGURE)
SUB_MODES = {CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS}

# Prompt suffixes per mode
PROMPT_SUFFIX = {
    EXEC: '>',
    PRIVILEGED: '#',
    CONFIGURE: '(config)#',
    CONFIG_IF: '(config-if)#',
    CONFIG_FW: '(config-fw)#',
    CONFIG_VPN: '(config-vpn)#',
    CONFIG_DHCP: '(config-dhcp)#',
    CONFIG_DNS: '(config-dns)#',
}

# Commands available in exec mode (read-only)
EXEC_COMMANDS = {'show', 'ping', 'traceroute', 'mtr', 'nslookup', 'dig', 'ssh', 'exit', 'enable', 'help'}

# Additional commands in privileged mode
PRIVILEGED_COMMANDS = EXEC_COMMANDS | {'configure', 'reload', 'copy', 'clear', 'disable', 'capture', 'iperf'}

# Commands in configure mode
CONFIGURE_COMMANDS = {'interface', 'firewall', 'vpn', 'dhcp', 'dns', 'hostname', 'nexus', 'exit', 'end', 'help', 'show'}


class ModeStack:
    """
    Tracks the current CLI mode and supports push/pop for sub-mode navigation.
    The stack always has at least one entry (the base mode).
    """

    def __init__(self):
        self._stack = [EXEC]
        self._context = {}  # Per-mode context (e.g., interface name for config-if)

    @property
    def current(self) -> str:
        """Return the current (top of stack) mode."""
        return self._stack[-1]

    @property
    def context(self) -> dict:
        """Return context data for the current mode."""
        return self._context.get(self.current, {})

    def push(self, mode: str, context: dict = None) -> None:
        """Push a new mode onto the stack."""
        if mode not in ALL_MODES:
            raise ValueError(f'Invalid mode: {mode}')
        self._stack.append(mode)
        if context:
            self._context[mode] = context

    def pop(self) -> str:
        """Pop the current mode and return to the previous one."""
        if len(self._stack) <= 1:
            return self._stack[0]
        old = self._stack.pop()
        self._context.pop(old, None)
        return self._stack[-1]

    def reset_to(self, mode: str) -> None:
        """Reset the stack to a specific mode, clearing everything above it."""
        if mode == EXEC:
            self._stack = [EXEC]
            self._context.clear()
        elif mode == PRIVILEGED:
            self._stack = [EXEC, PRIVILEGED]
            self._context.clear()
        elif mode == CONFIGURE:
            self._stack = [EXEC, PRIVILEGED, CONFIGURE]
            # Clear sub-mode contexts
            for m in SUB_MODES:
                self._context.pop(m, None)

    def is_in(self, mode: str) -> bool:
        """Check if a mode is anywhere in the stack."""
        return mode in self._stack

    def depth(self) -> int:
        """Return the stack depth."""
        return len(self._stack)

    def __repr__(self) -> str:
        return f'ModeStack({" > ".join(self._stack)})'
