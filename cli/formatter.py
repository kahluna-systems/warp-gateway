"""
Output formatting for the CLI shell.
Handles table alignment, key-value display, pagination, and section formatting.
All output is plain ASCII only -- no emojis, no ANSI codes, no Unicode box-drawing.
"""
import sys


def _sanitize(text: str) -> str:
    """Strip non-ASCII characters, keeping only printable ASCII (32-126), newlines, and CR."""
    out = []
    for ch in text:
        code = ord(ch)
        if ch in ('\n', '\r'):
            out.append(ch)
        elif 32 <= code <= 126:
            out.append(ch)
        else:
            out.append('?')
    return ''.join(out)


class OutputFormatter:
    """Formats command output for terminal display."""

    def __init__(self, terminal_width: int = 80, page_size: int = 24):
        self.terminal_width = terminal_width
        self.page_size = page_size

    def table(self, headers: list, rows: list, brief: bool = False) -> str:
        """
        Format data as an aligned ASCII table.

        Args:
            headers: List of column header strings.
            rows: List of lists, each inner list is a row of values.
            brief: If True, may truncate columns for compact display.

        Returns:
            Formatted table string with no trailing whitespace on any line.
        """
        if not headers:
            return ''

        headers = [_sanitize(str(h)) for h in headers]
        sanitized_rows = []
        for row in rows:
            sanitized_rows.append([_sanitize(str(cell)) for cell in row])

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in sanitized_rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(cell))
                else:
                    col_widths.append(len(cell))

        if brief:
            max_col = max(12, self.terminal_width // len(headers) - 2) if headers else 40
            col_widths = [min(w, max_col) for w in col_widths]

        # Build header line
        header_parts = []
        for i, h in enumerate(headers):
            w = col_widths[i] if i < len(col_widths) else len(h)
            header_parts.append(h.ljust(w))
        header_line = '  '.join(header_parts).rstrip()

        # Build separator
        sep_parts = []
        for w in col_widths:
            sep_parts.append('-' * w)
        sep_line = '  '.join(sep_parts).rstrip()

        # Build rows
        lines = [header_line, sep_line]
        for row in sanitized_rows:
            parts = []
            for i in range(len(col_widths)):
                cell = row[i] if i < len(row) else ''
                w = col_widths[i]
                if brief and len(cell) > w:
                    cell = cell[:w - 1] + '~'
                parts.append(cell.ljust(w))
            lines.append('  '.join(parts).rstrip())

        return '\n'.join(lines)

    def key_value(self, data: dict, indent: int = 0) -> str:
        """
        Format key-value pairs with aligned colons.

        Args:
            data: Dict of key -> value.
            indent: Number of spaces to indent each line.

        Returns:
            Formatted string.
        """
        if not data:
            return ''

        prefix = ' ' * indent
        max_key_len = max(len(_sanitize(str(k))) for k in data.keys())

        lines = []
        for key, value in data.items():
            k = _sanitize(str(key)).ljust(max_key_len)
            v = _sanitize(str(value))
            lines.append(f'{prefix}{k} : {v}')

        return '\n'.join(lines)

    def section(self, title: str, content: str) -> str:
        """
        Format a titled section with separator lines.

        Args:
            title: Section title.
            content: Section body text.

        Returns:
            Formatted section string.
        """
        title = _sanitize(title)
        content = _sanitize(content)
        sep = '-' * len(title)
        return f'{title}\n{sep}\n{content}'

    def paginate(self, text: str, output_fn=None) -> None:
        """
        Display text with --More-- pagination.

        Args:
            text: Full text to paginate.
            output_fn: Callable to write output. Defaults to sys.stdout.write.
        """
        if output_fn is None:
            output_fn = sys.stdout.write

        text = _sanitize(text)
        lines = text.split('\n')

        if len(lines) <= self.page_size:
            output_fn(text + '\n')
            return

        i = 0
        while i < len(lines):
            chunk = lines[i:i + self.page_size]
            output_fn('\n'.join(chunk) + '\n')
            i += self.page_size

            if i < len(lines):
                output_fn('--More--')
                try:
                    key = input()
                    if key.strip().lower() == 'q':
                        break
                    elif key == '':
                        # Enter: show one more line
                        if i < len(lines):
                            output_fn(lines[i] + '\n')
                            i += 1
                except (EOFError, KeyboardInterrupt):
                    output_fn('\n')
                    break

    def print(self, text: str) -> None:
        """Print sanitized text to stdout."""
        print(_sanitize(str(text)))
