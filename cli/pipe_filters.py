"""
Output pipe filters for the CLI shell.
Implements Juniper/Cisco-style output modifiers:
  | include <pattern>   -- grep for matching lines
  | exclude <pattern>   -- inverse grep
  | begin <pattern>     -- start from first match
  | count              -- count lines
  | last <n>           -- show last N lines
  | display json       -- format as JSON
  | display xml        -- format as XML
  | no-more            -- disable pagination
"""
import json
import re


def parse_pipe(line: str) -> tuple:
    """
    Split a command line on the pipe character.
    Returns (command, filter_chain) where filter_chain is a list of
    (filter_name, filter_args) tuples.

    Example:
        'show interfaces | include WAN | count'
        -> ('show interfaces', [('include', 'WAN'), ('count', '')])
    """
    if '|' not in line:
        return line, []

    parts = line.split('|', 1)
    command = parts[0].strip()
    filter_str = parts[1].strip()

    filters = []
    # Split on additional pipes
    for segment in filter_str.split('|'):
        segment = segment.strip()
        if not segment:
            continue

        tokens = segment.split(None, 1)
        filter_name = tokens[0].lower()
        filter_args = tokens[1] if len(tokens) > 1 else ''
        filters.append((filter_name, filter_args))

    return command, filters


def apply_filters(output: str, filters: list) -> tuple:
    """
    Apply a chain of filters to command output.

    Args:
        output: The raw command output string.
        filters: List of (filter_name, filter_args) tuples.

    Returns:
        (filtered_output, no_more) tuple. no_more is True if pagination
        should be disabled.
    """
    no_more = False

    for filter_name, filter_args in filters:
        if filter_name == 'include':
            output = _filter_include(output, filter_args)
        elif filter_name == 'exclude':
            output = _filter_exclude(output, filter_args)
        elif filter_name == 'begin':
            output = _filter_begin(output, filter_args)
        elif filter_name == 'count':
            output = _filter_count(output)
        elif filter_name == 'last':
            output = _filter_last(output, filter_args)
        elif filter_name == 'display':
            output = _filter_display(output, filter_args)
        elif filter_name == 'compare':
            output = _filter_compare(output, filter_args)
        elif filter_name in ('no-more', 'nomore'):
            no_more = True
        else:
            output = f'% Unknown filter: {filter_name}\n' + output

    return output, no_more


def get_filter_help() -> str:
    """Return help text for available pipe filters."""
    return """  Output modifiers:
  | include <pattern>   Show lines matching a pattern
  | exclude <pattern>   Hide lines matching a pattern
  | begin <pattern>     Start output from first matching line
  | count               Count the number of output lines
  | last <n>            Show the last N lines
  | compare             Show diff between running and startup config
  | compare rollback N  Show diff between running and rollback version N
  | display json        Format output as JSON
  | display xml         Format output as XML
  | no-more             Disable pagination for this command"""


# ── Filter implementations ───────────────────────────────────────────────────

def _filter_include(output: str, pattern: str) -> str:
    """Show only lines matching the pattern (case-insensitive)."""
    if not pattern:
        return output
    try:
        regex = re.compile(pattern, re.IGNORECASE)
        lines = output.split('\n')
        matched = [line for line in lines if regex.search(line)]
        return '\n'.join(matched)
    except re.error:
        # Fall back to simple string match
        lines = output.split('\n')
        matched = [line for line in lines if pattern.lower() in line.lower()]
        return '\n'.join(matched)


def _filter_exclude(output: str, pattern: str) -> str:
    """Hide lines matching the pattern (case-insensitive)."""
    if not pattern:
        return output
    try:
        regex = re.compile(pattern, re.IGNORECASE)
        lines = output.split('\n')
        filtered = [line for line in lines if not regex.search(line)]
        return '\n'.join(filtered)
    except re.error:
        lines = output.split('\n')
        filtered = [line for line in lines if pattern.lower() not in line.lower()]
        return '\n'.join(filtered)


def _filter_begin(output: str, pattern: str) -> str:
    """Start output from the first line matching the pattern."""
    if not pattern:
        return output
    lines = output.split('\n')
    for i, line in enumerate(lines):
        if pattern.lower() in line.lower():
            return '\n'.join(lines[i:])
    return ''  # Pattern not found


def _filter_count(output: str) -> str:
    """Count the number of non-empty lines."""
    lines = [line for line in output.split('\n') if line.strip()]
    return f'Count: {len(lines)} lines'


def _filter_last(output: str, args: str) -> str:
    """Show the last N lines."""
    try:
        n = int(args) if args else 10
    except ValueError:
        n = 10
    lines = output.split('\n')
    return '\n'.join(lines[-n:])


def _filter_display(output: str, format_type: str) -> str:
    """Convert output to JSON or XML format."""
    format_type = format_type.lower().strip()

    if format_type == 'json':
        return _to_json(output)
    elif format_type == 'xml':
        return _to_xml(output)
    else:
        return f'% Unknown display format: {format_type}\n% Available: json, xml\n' + output


def _to_json(output: str) -> str:
    """Convert CLI output to JSON. Handles tables and key-value pairs."""
    lines = output.strip().split('\n')
    if not lines:
        return '{}'

    # Try to detect if it's a table (has a separator line with dashes)
    sep_idx = None
    for i, line in enumerate(lines):
        if line.strip() and all(c in '- ' for c in line.strip()):
            sep_idx = i
            break

    if sep_idx is not None and sep_idx > 0:
        # Table format: header, separator, data rows
        headers = lines[sep_idx - 1].split()
        rows = []
        for line in lines[sep_idx + 1:]:
            if line.strip():
                values = line.split()
                row = {}
                for j, header in enumerate(headers):
                    row[header] = values[j] if j < len(values) else ''
                rows.append(row)
        return json.dumps(rows, indent=2)

    # Try key-value format (lines with " : " separator)
    kv = {}
    for line in lines:
        if ' : ' in line:
            key, _, value = line.partition(' : ')
            kv[key.strip()] = value.strip()
        elif ':' in line and not line.startswith('!'):
            key, _, value = line.partition(':')
            if key.strip() and value.strip():
                kv[key.strip()] = value.strip()

    if kv:
        return json.dumps(kv, indent=2)

    # Fall back: return as a JSON array of lines
    return json.dumps([line for line in lines if line.strip()], indent=2)


def _to_xml(output: str) -> str:
    """Convert CLI output to XML. Handles tables and key-value pairs."""
    lines = output.strip().split('\n')
    if not lines:
        return '<output/>'

    xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml_lines.append('<output>')

    # Try table detection
    sep_idx = None
    for i, line in enumerate(lines):
        if line.strip() and all(c in '- ' for c in line.strip()):
            sep_idx = i
            break

    if sep_idx is not None and sep_idx > 0:
        headers = lines[sep_idx - 1].split()
        for line in lines[sep_idx + 1:]:
            if line.strip():
                values = line.split()
                xml_lines.append('  <entry>')
                for j, header in enumerate(headers):
                    val = _xml_escape(values[j] if j < len(values) else '')
                    tag = header.lower().replace(' ', '-')
                    xml_lines.append(f'    <{tag}>{val}</{tag}>')
                xml_lines.append('  </entry>')
    else:
        # Key-value or raw lines
        for line in lines:
            if ' : ' in line:
                key, _, value = line.partition(' : ')
                tag = key.strip().lower().replace(' ', '-')
                val = _xml_escape(value.strip())
                xml_lines.append(f'  <{tag}>{val}</{tag}>')
            elif line.strip() and not line.startswith('!'):
                xml_lines.append(f'  <line>{_xml_escape(line.strip())}</line>')

    xml_lines.append('</output>')
    return '\n'.join(xml_lines)


def _xml_escape(s: str) -> str:
    """Escape special XML characters."""
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def _filter_compare(output: str, args: str) -> str:
    """
    Generate a unified diff between running config and a target.
    Usage:
        | compare              -- diff running vs startup
        | compare rollback <N> -- diff running vs rollback-N
    """
    try:
        from cli.config_serializer import ConfigSerializer
        serializer = ConfigSerializer()

        tokens = args.strip().split() if args else []

        if tokens and tokens[0].lower() == 'rollback':
            if len(tokens) < 2 or not tokens[1].isdigit():
                return '% Usage: | compare rollback <N>'
            version = int(tokens[1])
            return serializer.compare(target='rollback', version=version)
        else:
            return serializer.compare(target='startup')

    except Exception as e:
        return f'% Compare failed: {e}'
