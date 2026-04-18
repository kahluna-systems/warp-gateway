"""
Firewall rule CRUD — orchestrates database + iptables.
"""
import logging
from database import db
from models_new import FirewallRule, PortForward, AuditLog
from system import firewall as sys_fw
from services.interface_service import get_wan_interface, get_lan_interface

logger = logging.getLogger('warp.services.firewall')


def apply_default_policy():
    """Apply the default firewall policy on startup."""
    wan = get_wan_interface()
    lan = get_lan_interface()
    wan_name = wan.name if wan else 'eth0'
    lan_name = lan.name if lan else 'eth1'

    success = sys_fw.set_default_policy(wan_name, lan_name)
    if success:
        logger.info('Default firewall policy applied')
    else:
        logger.error('Failed to apply default firewall policy')
    return success


def list_rules():
    """Return all custom firewall rules from the database."""
    return FirewallRule.query.order_by(FirewallRule.priority, FirewallRule.id).all()


def add_custom_rule(chain, source=None, destination=None, port=None,
                    protocol=None, action='ACCEPT', priority=100, description=''):
    """Add a custom firewall rule to DB and iptables."""
    try:
        rule = FirewallRule(
            chain=chain,
            source=source,
            destination=destination,
            port=port,
            protocol=protocol,
            action=action,
            priority=priority,
            description=description,
            is_active=True,
        )
        db.session.add(rule)

        # Apply to iptables
        result = sys_fw.add_custom_rule(
            chain=chain,
            source=source,
            dest=destination,
            port=port,
            protocol=protocol,
            action=action,
        )

        if not result.success:
            db.session.rollback()
            return {'success': False, 'message': f'iptables error: {result.stderr or result.error}'}

        db.session.commit()
        AuditLog.log('firewall_rule_add', f'Added {action} rule on {chain}: {description}')
        db.session.commit()

        logger.info(f'Firewall rule added: {chain} {action} {description}')
        return {'success': True, 'rule': rule}

    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to add firewall rule: {e}')
        return {'success': False, 'message': str(e)}


def remove_custom_rule(rule_id):
    """Remove a custom firewall rule from DB and iptables."""
    try:
        rule = FirewallRule.query.get(rule_id)
        if not rule:
            return {'success': False, 'message': 'Rule not found'}

        # Remove from iptables (best effort — rule may not exist if iptables was flushed)
        from system.commander import run
        cmd = ['iptables', '-D', rule.chain]
        if rule.protocol:
            cmd.extend(['-p', rule.protocol])
        if rule.source:
            cmd.extend(['-s', rule.source])
        if rule.destination:
            cmd.extend(['-d', rule.destination])
        if rule.port and rule.protocol:
            cmd.extend(['--dport', str(rule.port)])
        cmd.extend(['-j', rule.action])
        run(cmd, sudo=True)

        desc = rule.description
        db.session.delete(rule)
        db.session.commit()

        AuditLog.log('firewall_rule_remove', f'Removed firewall rule: {desc}')
        db.session.commit()

        return {'success': True, 'message': 'Rule removed'}

    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to remove firewall rule {rule_id}: {e}')
        return {'success': False, 'message': str(e)}


def list_port_forwards():
    """Return all port forwarding rules."""
    return PortForward.query.all()


def add_port_forward(wan_port, lan_ip, lan_port, protocol='tcp', description=''):
    """Add a port forwarding rule to DB and iptables."""
    try:
        pf = PortForward(
            wan_port=wan_port,
            lan_ip=lan_ip,
            lan_port=lan_port,
            protocol=protocol,
            description=description,
            is_active=True,
        )
        db.session.add(pf)

        result = sys_fw.add_port_forward(wan_port, lan_ip, lan_port, protocol)
        if not result.success:
            db.session.rollback()
            return {'success': False, 'message': f'iptables error: {result.stderr or result.error}'}

        db.session.commit()
        AuditLog.log('port_forward_add', f'Port forward WAN:{wan_port} -> {lan_ip}:{lan_port}/{protocol}')
        db.session.commit()

        return {'success': True, 'port_forward': pf}

    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}


def remove_port_forward(pf_id):
    """Remove a port forwarding rule."""
    try:
        pf = PortForward.query.get(pf_id)
        if not pf:
            return {'success': False, 'message': 'Port forward not found'}

        sys_fw.remove_port_forward(pf.wan_port, pf.lan_ip, pf.lan_port, pf.protocol)

        db.session.delete(pf)
        db.session.commit()

        AuditLog.log('port_forward_remove', f'Removed port forward WAN:{pf.wan_port}')
        db.session.commit()

        return {'success': True, 'message': 'Port forward removed'}

    except Exception as e:
        db.session.rollback()
        return {'success': False, 'message': str(e)}


def sync_all_rules():
    """Re-apply all active DB rules to iptables. Called on startup after default policy."""
    rules = FirewallRule.query.filter_by(is_active=True).order_by(FirewallRule.priority).all()
    for rule in rules:
        sys_fw.add_custom_rule(
            chain=rule.chain,
            source=rule.source,
            dest=rule.destination,
            port=rule.port,
            protocol=rule.protocol,
            action=rule.action,
        )

    forwards = PortForward.query.filter_by(is_active=True).all()
    for pf in forwards:
        sys_fw.add_port_forward(pf.wan_port, pf.lan_ip, pf.lan_port, pf.protocol)

    logger.info(f'Synced {len(rules)} firewall rules and {len(forwards)} port forwards')


def get_iptables_rules():
    """Get current iptables rules for display."""
    return {
        'filter': sys_fw.list_rules('filter'),
        'nat': sys_fw.list_rules('nat'),
    }
