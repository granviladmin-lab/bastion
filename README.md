# Bastion

A Check Point SmartConsole style viewer for this machine's UFW firewall. It
shows the rulebase the way an Access Control policy reads, every packet the
firewall logged, and an overview of the gateway: default policies, who is
being dropped, and which listening services the network can actually reach.

It is read only and needs no root: rules come from `/etc/ufw/*.rules` and
`/etc/default/ufw`, logs from the kernel journal (`journalctl -k`), and
sockets from `ss`. To change rules, use `sudo ufw …`; Bastion notices the
change on disk and reloads. Each rule's details show its `ufw` equivalent.

## Views

- **Gateway** — firewall and service state, default policies, drops in the
  last 24 hours, top dropped sources, services and interfaces, and each
  listening socket judged against the rules (open, allowed for some, blocked,
  local only). Click a source or service to open its logs.
- **Security Policies** — incoming, outgoing and forwarded sections, each
  ending in its cleanup rule (the default policy), with hits counted from the
  logs. Implied rules from `before.rules` can be shown on top.
- **Logs & Monitor** — live log table with a 24 hour timeline, a time range,
  and a query bar. Select an entry for its log card and one-click filters.

UFW only logs blocked packets by default, so accept rules show hits only when
they log (`ufw allow log …`) or logging is raised (`ufw logging medium`).

## Query syntax

| Term | Matches |
| --- | --- |
| `src:10.0.0.5`, `src:10.0.0.0/8` | source address or subnet |
| `dst:…`, `ip:…` | destination, either side |
| `port:22`, `port:1000:2000`, `sport:…` | destination or source port |
| `proto:udp` | protocol |
| `action:drop` / `action:accept` | verdict |
| `dir:in` / `dir:out` / `dir:forward` | direction |
| `iface:eth0` | interface |
| `rule:3`, `rule:cleanup` | matched rule |
| `!term` | negates a term |
| anything else | free text over the raw log |

## Shortcuts

| Key | Action |
| --- | --- |
| `1` `2` `3` | Gateway, Security Policies, Logs |
| `/`, `Ctrl+F` | Search the policy or the logs |
| `Esc` | Clear the search or close details |
| `↑` `↓` | Move through rules or logs |
| `Space` | Pause or resume live logs |
| `I` | Show or hide implied rules |
| `R` | Reload rules and logs |
| `?` | Shortcut overlay |
| `Q` | Quit |

## Build

```sh
bin/build      # build/bastion
bin/test       # Qt Test, offscreen
bin/install    # makepkg -fsi, adds it to the app launcher
```
