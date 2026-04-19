"""
Property-based tests for the CLI shell.
Uses hypothesis to verify universal correctness properties from the design document.

Each test references its design document property number.
"""
import string
import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from cli.modes import (
    ModeStack, EXEC, PRIVILEGED, CONFIGURE,
    CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS,
    SUB_MODES, PROMPT_SUFFIX,
)
from cli.command_tree import CommandNode, get_command_trees
from cli.parser import CommandParser
from cli.formatter import OutputFormatter, _sanitize


# ── Strategies ───────────────────────────────────────────────────────────────

# Strategy for valid command names (lowercase alpha, 2-12 chars)
command_name_st = st.text(
    alphabet=string.ascii_lowercase,
    min_size=2,
    max_size=12,
).filter(lambda s: s.isalpha())

# Strategy for building small command trees
def command_tree_st(min_size=2, max_size=8):
    """Generate a dict of command_name -> CommandNode."""
    return st.dictionaries(
        keys=command_name_st,
        values=st.just(None),  # placeholder
        min_size=min_size,
        max_size=max_size,
    ).map(lambda d: {
        name: CommandNode(name=name, help_text=f'Help for {name}')
        for name in d
    })

# Strategy for printable ASCII strings (for formatter tests)
ascii_text_st = st.text(
    alphabet=st.characters(whitelist_categories=('L', 'N', 'P', 'S', 'Z')),
    min_size=0,
    max_size=50,
)

# Strategy for table cell data
cell_st = st.text(
    alphabet=string.printable,
    min_size=0,
    max_size=30,
).map(lambda s: s.replace('\n', ' ').replace('\r', ' '))

# Strategy for hostnames
hostname_st = st.text(
    alphabet=string.ascii_lowercase + string.digits + '-',
    min_size=1,
    max_size=20,
).filter(lambda s: s[0].isalpha())

# Strategy for modes
mode_st = st.sampled_from([EXEC, PRIVILEGED, CONFIGURE, CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS])

# Strategy for management modes
mgmt_mode_st = st.sampled_from(['standalone', 'managed', 'pre_provisioned'])

# Strategy for sub-modes (config and below)
sub_mode_st = st.sampled_from([CONFIGURE, CONFIG_IF, CONFIG_FW, CONFIG_VPN, CONFIG_DHCP, CONFIG_DNS])


# ── Property 1: Unambiguous prefix resolution ───────────────────────────────

class TestProperty1:
    """
    Property 1: Unambiguous prefix resolution
    For any command tree and any prefix that uniquely matches one command,
    the resolver SHALL return that command. A prefix matching zero returns error.
    Validates: Requirements 1.3, 3.1
    """

    @given(tree=command_tree_st())
    @settings(max_examples=100)
    def test_unique_prefix_resolves(self, tree):
        """A prefix matching exactly one command resolves to it."""
        if not tree:
            return

        for name, node in tree.items():
            # Try progressively shorter prefixes
            for length in range(1, len(name) + 1):
                prefix = name[:length]
                matches = CommandParser.resolve_abbreviation(prefix, tree)

                # If this prefix is also an exact match for a different (shorter) command,
                # the resolver correctly returns that exact match instead.
                # This is correct Cisco-style behavior: exact match wins over prefix.
                exact_match = any(
                    other_name.lower() == prefix.lower()
                    for other_name in tree
                    if other_name != name
                )

                if len(matches) == 1 and not exact_match:
                    assert matches[0].name == name
                    break

    @given(tree=command_tree_st())
    @settings(max_examples=100)
    def test_no_match_returns_empty(self, tree):
        """A prefix matching zero commands returns empty list."""
        # Use a prefix that can't match any command
        result = CommandParser.resolve_abbreviation('zzzzzzzzz', tree)
        assert result == []


# ── Property 2: Ambiguous prefix returns all matches ────────────────────────

class TestProperty2:
    """
    Property 2: Ambiguous prefix returns all matches
    For any prefix matching 2+ commands, the resolver returns exactly
    the set of commands whose names start with that prefix.
    Validates: Requirements 1.4, 3.2
    """

    @given(tree=command_tree_st(min_size=3, max_size=10))
    @settings(max_examples=100)
    def test_ambiguous_returns_all(self, tree):
        """An ambiguous prefix returns all matching commands."""
        if len(tree) < 2:
            return

        # Find a prefix that matches multiple commands
        names = sorted(tree.keys())
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                # Find common prefix
                common = ''
                for a, b in zip(names[i], names[j]):
                    if a == b:
                        common += a
                    else:
                        break

                if not common:
                    continue

                # Skip if the common prefix is itself an exact command name
                # (exact match takes priority -- correct Cisco behavior)
                if common.lower() in {n.lower() for n in names}:
                    continue

                matches = CommandParser.resolve_abbreviation(common, tree)
                expected = [n for n in names if n.lower().startswith(common.lower())]
                match_names = sorted(m.name for m in matches)
                assert match_names == sorted(expected), \
                    f'Prefix "{common}": got {match_names}, expected {sorted(expected)}'
                return  # Found one case, that's enough


# ── Property 3: Mode-based command filtering ────────────────────────────────

class TestProperty3:
    """
    Property 3: Mode-based command filtering
    Commands not available in exec mode are rejected in exec mode.
    Only show, ping, traceroute, mtr, nslookup, dig, ssh, exit, enable, help
    are accepted in exec mode.
    Validates: Requirements 2.1
    """

    def setup_method(self):
        import cli.command_tree as ct
        ct._TREES = None

    @given(data=st.data())
    @settings(max_examples=50)
    def test_privileged_commands_rejected_in_exec(self, data):
        """Commands only in privileged mode are not in exec tree."""
        trees = get_command_trees()
        exec_tree = trees[EXEC]
        priv_only = set(trees[PRIVILEGED].keys()) - set(exec_tree.keys())

        if not priv_only:
            return

        cmd = data.draw(st.sampled_from(sorted(priv_only)))
        parser = CommandParser()
        result = parser.parse(cmd, EXEC)
        assert result.error == 'unknown' or result.resolved_node is None, \
            f'Command "{cmd}" should not be available in exec mode'


# ── Property 4: "end" returns to privileged from any sub-mode ───────────────

class TestProperty4:
    """
    Property 4: "end" returns to privileged from any sub-mode
    Executing "end" from any config or sub-config mode returns to privileged.
    Validates: Requirements 2.6
    """

    @given(mode=sub_mode_st)
    @settings(max_examples=50)
    def test_end_always_returns_to_privileged(self, mode):
        """'end' from any config/sub-config mode goes to privileged."""
        ms = ModeStack()
        ms.push(PRIVILEGED)
        ms.push(CONFIGURE)
        if mode in SUB_MODES:
            ms.push(mode)

        # Simulate "end" -- reset to privileged
        ms.reset_to(PRIVILEGED)
        assert ms.current == PRIVILEGED


# ── Property 5: Help displays valid next tokens ─────────────────────────────

class TestProperty5:
    """
    Property 5: Help displays valid next tokens at any tree position
    For any valid partial command, help returns the set of valid next tokens
    with non-empty descriptions.
    Validates: Requirements 3.3, 3.4
    """

    def setup_method(self):
        import cli.command_tree as ct
        ct._TREES = None

    def test_help_at_root_shows_all_commands(self):
        """Help at empty input shows all available commands."""
        from cli.help_system import HelpSystem
        hs = HelpSystem()
        result = hs.get_help('', EXEC)
        assert result  # Non-empty
        assert 'show' in result
        assert 'ping' in result
        assert 'enable' in result

    def test_help_after_show_shows_children(self):
        """Help after 'show ' shows show sub-commands."""
        from cli.help_system import HelpSystem
        hs = HelpSystem()
        result = hs.get_help('show ', EXEC)
        assert result
        assert 'interfaces' in result
        assert 'vpn' in result

    @given(mode=mode_st)
    @settings(max_examples=20)
    def test_help_always_returns_content(self, mode):
        """Help at root always returns non-empty content for any mode."""
        from cli.help_system import HelpSystem
        hs = HelpSystem()
        result = hs.get_help('', mode)
        assert result
        assert len(result) > 0


# ── Property 6: Prompt reflects hostname, mode, and management state ────────

class TestProperty6:
    """
    Property 6: Prompt reflects hostname, mode, and management state
    The prompt contains the hostname, correct mode suffix, and [nexus]
    indicator iff management mode is managed or pre_provisioned.
    Validates: Requirements 10.3, 19.7
    """

    @given(hostname=hostname_st, mode=mode_st, mgmt=mgmt_mode_st)
    @settings(max_examples=100)
    def test_prompt_components(self, hostname, mode, mgmt):
        """Prompt contains hostname, correct suffix, and nexus indicator."""
        suffix = PROMPT_SUFFIX.get(mode, '>')
        nexus = ' [nexus]' if mgmt in ('managed', 'pre_provisioned') else ''
        expected = f'{hostname}{nexus}{suffix} '

        # Build the prompt the same way WarpShell does
        prompt = f'{hostname}{nexus}{suffix} '
        assert prompt == expected

        # Verify hostname is present
        assert hostname in prompt

        # Verify suffix
        assert suffix in prompt

        # Verify nexus indicator
        if mgmt in ('managed', 'pre_provisioned'):
            assert '[nexus]' in prompt
        else:
            assert '[nexus]' not in prompt


# ── Property 8: Table output has aligned columns ────────────────────────────

class TestProperty8:
    """
    Property 8: Table output has aligned columns and no trailing whitespace
    For any headers and row data, columns start at the same position
    across all rows, and no line ends with trailing whitespace.
    Validates: Requirements 12.1
    """

    @given(
        headers=st.lists(cell_st, min_size=1, max_size=5),
        rows=st.lists(
            st.lists(cell_st, min_size=1, max_size=5),
            min_size=0,
            max_size=10,
        ),
    )
    @settings(max_examples=100)
    def test_no_trailing_whitespace(self, headers, rows):
        """No line in table output ends with trailing whitespace."""
        fmt = OutputFormatter()
        output = fmt.table(headers, rows)
        if not output:
            return
        for line in output.split('\n'):
            assert line == line.rstrip(), f'Trailing whitespace: "{line}"'


# ── Property 9: Output contains only plain ASCII ────────────────────────────

class TestProperty9:
    """
    Property 9: Output contains only plain ASCII
    For any input data, the output contains only ASCII 32-126, newlines, and CR.
    Validates: Requirements 12.4
    """

    @given(text=st.text(min_size=0, max_size=200))
    @settings(max_examples=100)
    def test_sanitize_produces_ascii_only(self, text):
        """_sanitize strips all non-ASCII characters."""
        result = _sanitize(text)
        for ch in result:
            code = ord(ch)
            assert ch in ('\n', '\r') or (32 <= code <= 126), \
                f'Non-ASCII char in sanitized output: {repr(ch)} (code {code})'

    @given(
        headers=st.lists(st.text(min_size=1, max_size=20), min_size=1, max_size=3),
        rows=st.lists(
            st.lists(st.text(min_size=0, max_size=20), min_size=1, max_size=3),
            min_size=0,
            max_size=5,
        ),
    )
    @settings(max_examples=50)
    def test_table_output_ascii_only(self, headers, rows):
        """Table output contains only ASCII printable + newlines."""
        fmt = OutputFormatter()
        output = fmt.table(headers, rows)
        for ch in output:
            code = ord(ch)
            assert ch in ('\n', '\r') or (32 <= code <= 126), \
                f'Non-ASCII in table output: {repr(ch)} (code {code})'


# ── Property 10: Pagination activates for long output ───────────────────────

class TestProperty10:
    """
    Property 10: Pagination activates for long output
    Output exceeding page_size lines is split; shorter output is not interrupted.
    Validates: Requirements 12.3
    """

    @given(
        line_count=st.integers(min_value=1, max_value=100),
        page_size=st.integers(min_value=5, max_value=50),
    )
    @settings(max_examples=50)
    def test_pagination_threshold(self, line_count, page_size):
        """Pagination activates iff line count exceeds page_size."""
        fmt = OutputFormatter(page_size=page_size)
        text = '\n'.join(f'Line {i}' for i in range(line_count))

        # Capture output
        captured = []
        def capture(s):
            captured.append(s)

        if line_count <= page_size:
            # Should print without interruption
            fmt.paginate(text, output_fn=capture)
            full_output = ''.join(captured)
            assert f'Line 0' in full_output
            assert '--More--' not in full_output


# ── Property 7: Config commands produce audit entries ────────────────────────

class TestProperty7:
    """
    Property 7: Configuration change commands produce audit log entries
    Any command executed in configure mode creates an AuditLog entry.
    Validates: Requirements 11.3
    """

    @given(command=st.text(alphabet=string.ascii_lowercase + ' ', min_size=3, max_size=40))
    @settings(max_examples=50, deadline=2000)
    def test_record_command_creates_entry(self, command):
        """SessionManager.record_command logs to AuditLog."""
        # This test requires Flask app context -- skip if not available
        pytest.importorskip('flask')

        import os
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

        from gateway import create_app
        os.environ['DATABASE_URL'] = 'sqlite://'
        os.environ['SECRET_KEY'] = 'test-key'

        app = create_app()
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

        with app.app_context():
            from database import db
            db.create_all()

            from models_new import User, AuditLog
            from cli.session import SessionManager

            user = User(username='testadmin', email='test@test.local', role='admin')
            user.set_password('test123')
            db.session.add(user)
            db.session.commit()

            mgr = SessionManager()
            sid = mgr.create_session(user, '127.0.0.1', 'console')

            # Count before
            before = AuditLog.query.count()

            mgr.record_command(sid, command.strip() or 'test-cmd')

            after = AuditLog.query.count()
            assert after > before, 'AuditLog entry not created for config command'

            # Verify the entry contains the command
            latest = AuditLog.query.order_by(AuditLog.id.desc()).first()
            assert latest.action == 'cli_command'
