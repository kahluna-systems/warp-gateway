"""
Kernel VLAN operations.
Creates, destroys, and manages 802.1Q sub-interfaces and 802.1ad QinQ interfaces.
All operations go through commander.py for safe execution.
"""
import json
import logging
from system.commander import run

logger = logging.getLogger('warp.system.vlan')


def get_sub_interface_name(parent: str, vlan_id: int) -> str:
    """Return canonical sub-interface name: '<parent>.<vlan_id>'"""
    return f'{parent}.{vlan_id}'


def create_sub_interface(parent: str, vlan_id: int):
    """Create an 802.1Q sub-interface and bring it up."""
    name = get_sub_interface_name(parent, vlan_id)

    result = run(['ip', 'link', 'add', 'link', parent, 'name', name,
                  'type', 'vlan', 'id', str(vlan_id)], sudo=True)
    if not result.success:
        logger.error(f'Failed to create VLAN sub-interface {name}: {result.stderr}')
        return result

    up_result = run(['ip', 'link', 'set', name, 'up'], sudo=True)
    if not up_result.success:
        logger.error(f'Failed to bring up {name}: {up_result.stderr}')
        return up_result

    logger.info(f'VLAN sub-interface {name} created and up')
    return result


def delete_sub_interface(parent: str, vlan_id: int):
    """Delete a VLAN sub-interface."""
    name = get_sub_interface_name(parent, vlan_id)
    result = run(['ip', 'link', 'delete', name], sudo=True)
    if result.success:
        logger.info(f'VLAN sub-interface {name} deleted')
    else:
        logger.error(f'Failed to delete {name}: {result.stderr}')
    return result


def bring_up_sub_interface(parent: str, vlan_id: int):
    """Bring a VLAN sub-interface up."""
    name = get_sub_interface_name(parent, vlan_id)
    return run(['ip', 'link', 'set', name, 'up'], sudo=True)


def sub_interface_exists(parent: str, vlan_id: int) -> bool:
    """Check if a VLAN sub-interface exists in the kernel."""
    name = get_sub_interface_name(parent, vlan_id)
    result = run(['ip', 'link', 'show', name])
    return result.success


def create_qinq_outer(parent: str, s_vlan_id: int):
    """Create 802.1ad outer S-VLAN interface."""
    name = get_sub_interface_name(parent, s_vlan_id)
    result = run(['ip', 'link', 'add', 'link', parent, 'name', name,
                  'type', 'vlan', 'proto', '802.1ad', 'id', str(s_vlan_id)], sudo=True)
    if result.success:
        run(['ip', 'link', 'set', name, 'up'], sudo=True)
        logger.info(f'QinQ outer S-VLAN {name} created')
    else:
        logger.error(f'Failed to create QinQ outer {name}: {result.stderr}')
    return result


def create_qinq_inner(parent: str, s_vlan_id: int, c_vlan_id: int):
    """Create inner C-VLAN on an existing S-VLAN interface."""
    outer = get_sub_interface_name(parent, s_vlan_id)
    inner = f'{outer}.{c_vlan_id}'
    result = run(['ip', 'link', 'add', 'link', outer, 'name', inner,
                  'type', 'vlan', 'id', str(c_vlan_id)], sudo=True)
    if result.success:
        run(['ip', 'link', 'set', inner, 'up'], sudo=True)
        logger.info(f'QinQ inner C-VLAN {inner} created')
    else:
        logger.error(f'Failed to create QinQ inner {inner}: {result.stderr}')
    return result


def delete_qinq(parent: str, s_vlan_id: int, c_vlan_id: int = None):
    """Delete QinQ interfaces. Inner first, then outer if no c_vlan_id."""
    outer = get_sub_interface_name(parent, s_vlan_id)

    if c_vlan_id is not None:
        inner = f'{outer}.{c_vlan_id}'
        run(['ip', 'link', 'delete', inner], sudo=True)
        logger.info(f'QinQ inner {inner} deleted')
    else:
        # Delete outer (and all inners with it)
        result = run(['ip', 'link', 'delete', outer], sudo=True)
        if result.success:
            logger.info(f'QinQ outer {outer} deleted')
        return result


def list_kernel_vlans() -> list:
    """List all VLAN sub-interfaces currently in the kernel."""
    result = run(['ip', '-j', 'link', 'show', 'type', 'vlan'])
    if not result.success:
        return []
    try:
        links = json.loads(result.stdout)
        return [{'name': l.get('ifname', ''), 'link': l.get('link', '')} for l in links]
    except (json.JSONDecodeError, KeyError):
        return []
