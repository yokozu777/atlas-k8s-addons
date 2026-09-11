"""Resolve debug tooling host specifications against Ansible inventory groups."""


def expand_debug_tooling_hosts(spec, groups):
    """Expand comma-separated inventory groups, group patterns, or host names."""
    if not spec:
        return []

    hosts = []
    groups = groups or {}

    for token in spec.replace(' ', '').split(','):
        if not token:
            continue
        if ':' in token:
            for group_name in token.split(':'):
                if group_name in groups:
                    hosts.extend(groups[group_name])
            continue
        if token in groups:
            hosts.extend(groups[token])
            continue
        hosts.append(token)

    return sorted(set(hosts))


class FilterModule:
    def filters(self):
        return {
            'expand_debug_tooling_hosts': expand_debug_tooling_hosts,
        }
