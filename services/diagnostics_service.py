"""
Network diagnostic tools — ping, traceroute, DNS lookup, packet capture, MTR.
"""
import logging
from system.commander import run, which

logger = logging.getLogger('warp.services.diagnostics')


def ping(target, count=4):
    """Run ping to a target."""
    result = run(['ping', '-c', str(count), '-W', '3', target], timeout=count * 5 + 5)
    return {
        'success': result.success,
        'output': result.stdout if result.success else result.stderr or result.error,
        'target': target,
        'tool': 'ping',
    }


def traceroute(target, max_hops=30):
    """Run traceroute to a target."""
    if not which('traceroute'):
        return {'success': False, 'output': 'traceroute is not installed', 'tool': 'traceroute'}

    result = run(['traceroute', '-m', str(max_hops), '-w', '3', target], timeout=max_hops * 5)
    return {
        'success': result.success,
        'output': result.stdout if result.success else result.stderr or result.error,
        'target': target,
        'tool': 'traceroute',
    }


def dns_lookup(query, record_type='A', server=None):
    """Run a DNS lookup using dig."""
    if not which('dig'):
        return {'success': False, 'output': 'dig (dnsutils) is not installed', 'tool': 'dns_lookup'}

    cmd = ['dig', query, record_type, '+short']
    if server:
        cmd.insert(1, f'@{server}')

    result = run(cmd, timeout=10)
    return {
        'success': result.success,
        'output': result.stdout if result.success else result.stderr or result.error,
        'query': query,
        'record_type': record_type,
        'tool': 'dns_lookup',
    }


def mtr(target, count=10):
    """Run MTR (My Traceroute) to a target."""
    if not which('mtr'):
        return {'success': False, 'output': 'mtr is not installed', 'tool': 'mtr'}

    result = run(['mtr', '--report', '--report-cycles', str(count), target], timeout=count * 10)
    return {
        'success': result.success,
        'output': result.stdout if result.success else result.stderr or result.error,
        'target': target,
        'tool': 'mtr',
    }


def packet_capture(interface, filter_expr='', count=50, duration=10):
    """Run a packet capture using tcpdump."""
    if not which('tcpdump'):
        return {'success': False, 'output': 'tcpdump is not installed', 'tool': 'packet_capture'}

    cmd = ['tcpdump', '-i', interface, '-c', str(count), '-nn', '-l']
    if filter_expr:
        cmd.extend(filter_expr.split())

    result = run(cmd, sudo=True, timeout=duration + 5)
    return {
        'success': result.success,
        'output': result.stdout if result.success else result.stderr or result.error,
        'interface': interface,
        'tool': 'packet_capture',
    }


def get_available_tools():
    """Check which diagnostic tools are available."""
    tools = {
        'ping': which('ping') is not None,
        'traceroute': which('traceroute') is not None,
        'dig': which('dig') is not None,
        'mtr': which('mtr') is not None,
        'tcpdump': which('tcpdump') is not None,
        'iperf3': which('iperf3') is not None,
    }
    return tools
