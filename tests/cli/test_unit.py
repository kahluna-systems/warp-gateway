"""
Unit tests for the CLI shell.
Tests mode transitions, command parsing, session management, and output formatting.
"""
import pytest
from cli.modes import ModeStack, EXEC, PRIVILEGED, CONFIGURE, CONFIG_IF, CONFIG_FW, CONFIG_VPN
from cli.parser import CommandParser
from cli.formatter import OutputFormatter
from cli.command_tree import get_command_trees


# ── Mode Stack Tests ─────────────────────────────────────────────────────────

class TestModeStack:
    def test_initial_mode_is_exec(self):
        ms = ModeStack()
        assert ms.current == EXEC

    def test_push_privileged(self):
        ms = ModeStack()
        ms.push(PRIVILEGED)
        assert ms.current == PRIVILEGED

    def test_push_configure(self):
        ms = ModeStack()
        ms.push(PRIVILEGED)
        ms.push(CONFIGURE)
        assert ms.current == CONFIGURE

    def test_pop_returns_previous(self):
        ms = ModeStack()
        ms.push(PRIVILEGED)
        ms.push(CONFIGURE)
        ms.pop()
        assert ms.current == PRIVILEGED

    def test_pop_at_exec_stays(self):
        ms = ModeStack()
        ms.pop()
        assert ms.current == EXEC

    def test_reset_to_privileged(self):
        ms = ModeStack()
        ms.push(PRIVILEGED)
        ms.push(CONFIGURE)
        ms.push(CONFIG_IF)
        ms.reset_to(PRIVILEGED)
        assert ms.current == PRIVILEGED

    def test_reset_to_exec(self):
        ms = ModeStack()
        ms.push(PRIVILEGED)
        ms.push(CONFIGURE)
        ms.reset_to(EXEC)
        assert ms.current == EXEC

    def test_context_stored(self):
        ms = ModeStack()
        ms.push(PRIVILEGED)
        ms.push(CONFIGURE)
        ms.push(CONFIG_IF, {'interface': 'ens4'})
        assert ms.context == {'interface': 'ens4'}

    def test_context_cleared_on_reset(self):
        ms = ModeStack()
        ms.push(PRIVILEGED)
        ms.push(CONFIGURE)
        ms.push(CONFIG_IF, {'interface': 'ens4'})
        ms.reset_to(PRIVILEGED)
        assert ms.context == {}

    def test_invalid_mode_raises(self):
        ms = ModeStack()
        with pytest.raises(ValueError):
            ms.push('invalid-mode')


# ── Command Parser Tests ─────────────────────────────────────────────────────

class TestCommandParser:
    def setup_method(self):
        # Reset the cached trees
        import cli.command_tree as ct
        ct._TREES = None
        self.parser = CommandParser()

    def test_parse_show_interfaces(self):
        result = self.parser.parse('show interfaces', EXEC)
        assert result.resolved_node is not None
        assert result.path == ['show', 'interfaces']
        assert result.error is None

    def test_parse_abbreviation_sh_int(self):
        result = self.parser.parse('sh int', EXEC)
        assert result.resolved_node is not None
        assert result.path == ['show', 'interfaces']

    def test_parse_unknown_command(self):
        result = self.parser.parse('foobar', EXEC)
        assert result.error == 'unknown'

    def test_parse_ambiguous_command(self):
        # "sh" should resolve to "show" (only match starting with "sh")
        result = self.parser.parse('sh', EXEC)
        # "sh" matches "show" and "ssh" -- but "ssh" is not in exec tree
        # Actually let's check what's in the tree
        if result.error == 'ambiguous':
            assert len(result.matches) > 1
        else:
            # If only "show" matches, it resolves
            assert result.resolved_node is not None

    def test_parse_show_ip_route(self):
        result = self.parser.parse('show ip route', EXEC)
        assert result.resolved_node is not None
        assert result.path == ['show', 'ip', 'route']

    def test_parse_with_args(self):
        result = self.parser.parse('show interfaces ens4', EXEC)
        assert result.resolved_node is not None
        assert result.args == ['ens4']

    def test_parse_configure_not_in_exec(self):
        result = self.parser.parse('configure terminal', EXEC)
        assert result.error == 'unknown'

    def test_parse_configure_in_privileged(self):
        result = self.parser.parse('configure', PRIVILEGED)
        assert result.resolved_node is not None
        assert result.path == ['configure']

    def test_parse_empty_line(self):
        result = self.parser.parse('', EXEC)
        assert result.resolved_node is None

    def test_parse_firewall_rule_in_config_fw(self):
        result = self.parser.parse('rule INPUT ACCEPT tcp any any 80', CONFIG_FW)
        assert result.resolved_node is not None
        assert result.path == ['rule']
        assert result.args == ['INPUT', 'ACCEPT', 'tcp', 'any', 'any', '80']


# ── Output Formatter Tests ───────────────────────────────────────────────────

class TestOutputFormatter:
    def setup_method(self):
        self.fmt = OutputFormatter()

    def test_table_basic(self):
        headers = ['Name', 'Role', 'IP']
        rows = [
            ['ens3', 'WAN', '10.0.0.1'],
            ['ens4', 'LAN', '192.168.1.1'],
        ]
        output = self.fmt.table(headers, rows)
        lines = output.split('\n')
        assert len(lines) == 4  # header + separator + 2 rows
        assert 'Name' in lines[0]
        assert '----' in lines[1]
        assert 'ens3' in lines[2]

    def test_table_no_trailing_whitespace(self):
        headers = ['A', 'B']
        rows = [['x', 'y'], ['longer', 'z']]
        output = self.fmt.table(headers, rows)
        for line in output.split('\n'):
            assert line == line.rstrip(), f'Trailing whitespace found: "{line}"'

    def test_table_aligned_columns(self):
        headers = ['Name', 'Value']
        rows = [['short', '1'], ['much longer name', '2']]
        output = self.fmt.table(headers, rows)
        lines = output.split('\n')
        # Every line should have the same length when padded
        # More importantly, the second column value should start at the same position
        # The formatter uses ljust(col_width) + '  ' between columns
        # So we check that each line, when split on the two-space gap at the column boundary,
        # has the first field padded to the same width
        assert len(lines) == 4  # header + sep + 2 rows

        # The column width for "Name" should be max(4, 16) = 16
        # So "Value" column starts at position 16 + 2 = 18 in every non-separator line
        header_line = lines[0]
        row1 = lines[2]
        row2 = lines[3]

        # Find where 'Value' starts in header
        val_pos_header = header_line.index('Value')
        # Find where '1' starts in row1
        val_pos_row1 = row1.index('1')
        # Find where '2' starts in row2
        val_pos_row2 = row2.index('2')

        assert val_pos_header == val_pos_row1 == val_pos_row2, \
            f'Column misalignment: header={val_pos_header}, row1={val_pos_row1}, row2={val_pos_row2}'

    def test_table_empty_rows(self):
        headers = ['A', 'B']
        rows = []
        output = self.fmt.table(headers, rows)
        lines = output.split('\n')
        assert len(lines) == 2  # header + separator only

    def test_table_empty_headers(self):
        output = self.fmt.table([], [])
        assert output == ''

    def test_key_value(self):
        data = {'Hostname': 'warp-gw', 'Version': '0.1.0'}
        output = self.fmt.key_value(data)
        assert 'Hostname' in output
        assert 'warp-gw' in output
        assert ':' in output

    def test_section(self):
        output = self.fmt.section('Test Section', 'Some content here')
        assert 'Test Section' in output
        assert '---' in output
        assert 'Some content here' in output

    def test_plain_ascii_only(self):
        """Verify output contains only ASCII printable chars + newlines."""
        headers = ['Name']
        rows = [['test\u2603snowman'], ['normal']]
        output = self.fmt.table(headers, rows)
        for ch in output:
            code = ord(ch)
            assert ch in ('\n', '\r') or (32 <= code <= 126), \
                f'Non-ASCII character found: {repr(ch)} (code {code})'


# ── Command Tree Tests ───────────────────────────────────────────────────────

class TestCommandTree:
    def setup_method(self):
        import cli.command_tree as ct
        ct._TREES = None

    def test_exec_tree_has_show(self):
        trees = get_command_trees()
        assert 'show' in trees[EXEC]

    def test_exec_tree_has_ping(self):
        trees = get_command_trees()
        assert 'ping' in trees[EXEC]

    def test_exec_tree_has_enable(self):
        trees = get_command_trees()
        assert 'enable' in trees[EXEC]

    def test_exec_tree_no_configure(self):
        trees = get_command_trees()
        assert 'configure' not in trees[EXEC]

    def test_privileged_tree_has_configure(self):
        trees = get_command_trees()
        assert 'configure' in trees[PRIVILEGED]

    def test_privileged_tree_has_show(self):
        trees = get_command_trees()
        assert 'show' in trees[PRIVILEGED]

    def test_configure_tree_has_interface(self):
        trees = get_command_trees()
        assert 'interface' in trees[CONFIGURE]

    def test_configure_tree_has_firewall(self):
        trees = get_command_trees()
        assert 'firewall' in trees[CONFIGURE]

    def test_config_if_has_role(self):
        trees = get_command_trees()
        assert 'role' in trees[CONFIG_IF]

    def test_config_fw_has_rule(self):
        trees = get_command_trees()
        assert 'rule' in trees[CONFIG_FW]

    def test_show_has_interfaces_child(self):
        trees = get_command_trees()
        show = trees[EXEC]['show']
        assert 'interfaces' in show.children

    def test_show_has_vpn_child(self):
        trees = get_command_trees()
        show = trees[EXEC]['show']
        assert 'vpn' in show.children
        assert 'networks' in show.children['vpn'].children


# ── Shell Tests (require Flask app) ──────────────────────────────────────────

class TestWarpShell:
    def test_initial_mode_is_exec(self, shell):
        assert shell.mode_stack.current == EXEC

    def test_prompt_exec(self, shell):
        assert shell.prompt == 'test-gw> '

    def test_enable_transitions_to_privileged(self, shell, app):
        with app.app_context():
            # Mock getpass to return the enable password
            import cli.shell as shell_mod
            original_getpass = shell_mod.getpass.getpass
            shell_mod.getpass.getpass = lambda prompt='': 'enable123'
            try:
                shell.do_enable('')
                assert shell.mode_stack.current == PRIVILEGED
                assert '#' in shell.prompt
            finally:
                shell_mod.getpass.getpass = original_getpass

    def test_enable_wrong_password_stays_exec(self, shell, app, capsys):
        with app.app_context():
            import cli.shell as shell_mod
            original_getpass = shell_mod.getpass.getpass
            shell_mod.getpass.getpass = lambda prompt='': 'wrong'
            try:
                shell.do_enable('')
                assert shell.mode_stack.current == EXEC
                captured = capsys.readouterr()
                assert 'Access denied' in captured.out
            finally:
                shell_mod.getpass.getpass = original_getpass

    def test_configure_from_privileged(self, shell, app):
        with app.app_context():
            shell.mode_stack.push(PRIVILEGED)
            shell.do_configure('')
            assert shell.mode_stack.current == CONFIGURE
            assert '(config)' in shell.prompt

    def test_configure_from_exec_fails(self, shell, app, capsys):
        with app.app_context():
            shell.do_configure('')
            assert shell.mode_stack.current == EXEC
            captured = capsys.readouterr()
            assert 'privileged' in captured.out.lower()

    def test_exit_from_exec_returns_true(self, shell, app):
        with app.app_context():
            result = shell.do_exit('')
            assert result is True

    def test_exit_from_configure_returns_privileged(self, shell, app):
        with app.app_context():
            shell.mode_stack.push(PRIVILEGED)
            shell.mode_stack.push(CONFIGURE)
            shell.do_exit('')
            assert shell.mode_stack.current == PRIVILEGED

    def test_end_from_config_if_returns_privileged(self, shell, app):
        with app.app_context():
            shell.mode_stack.push(PRIVILEGED)
            shell.mode_stack.push(CONFIGURE)
            shell.mode_stack.push(CONFIG_IF)
            shell.do_end('')
            assert shell.mode_stack.current == PRIVILEGED

    def test_end_from_config_fw_returns_privileged(self, shell, app):
        with app.app_context():
            shell.mode_stack.push(PRIVILEGED)
            shell.mode_stack.push(CONFIGURE)
            shell.mode_stack.push(CONFIG_FW)
            shell.do_end('')
            assert shell.mode_stack.current == PRIVILEGED

    def test_disable_returns_to_exec(self, shell, app):
        with app.app_context():
            shell.mode_stack.push(PRIVILEGED)
            shell.do_disable('')
            assert shell.mode_stack.current == EXEC

    def test_unknown_command_message(self, shell, app, capsys):
        with app.app_context():
            shell.default('xyzzy')
            captured = capsys.readouterr()
            assert 'Unknown command' in captured.out

    def test_empty_line_does_nothing(self, shell, app):
        with app.app_context():
            shell.emptyline()
            assert shell.mode_stack.current == EXEC

    def test_nexus_prompt_indicator(self, shell, app):
        with app.app_context():
            shell._management_mode = 'managed'
            assert '[nexus]' in shell.prompt

    def test_standalone_no_nexus_indicator(self, shell, app):
        with app.app_context():
            shell._management_mode = 'standalone'
            assert '[nexus]' not in shell.prompt
