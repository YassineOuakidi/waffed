# 01 — Topology and IP Plan

## Goal of the topology

The topology separates the attacker/client side from the vulnerable backend. DVWA is placed behind the WAF, and the WAF is the only machine that should be able to talk to DVWA directly.

The expected path is:

```text
Kali / Client
      |
Client LAN
      |
pfSense
      |
WAF front network
      |
WAF/Zorin
      |
Backend LAN
      |
DVWA
```

![EVE-NG topology](assets/01_topology_canvas.png)

## Network zones

| Zone | Subnet | Role |
|---|---|---|
| Client LAN | `192.168.10.0/24` | Kali attacker and optional normal client. |
| WAF front network | `10.10.10.0/24` | pfSense to WAF/Zorin. |
| Backend LAN | `10.10.20.0/24` | WAF/Zorin to DVWA. |
| Management cloud | `172.16.42.0/24` | Temporary Internet/package access for lab VMs. |

The management cloud is not part of the security path. It was used only to install packages and download dependencies.

## Final IP plan

| Machine | Interface | IP address | Gateway / route |
|---|---|---:|---|
| Kali | `eth0` | `192.168.10.10/24` | `192.168.10.1` |
| pfSense LAN | `vtnet0` | `192.168.10.1/24` | N/A |
| pfSense WAF side | `vtnet1` | `10.10.10.1/24` | N/A |
| WAF/Zorin front | `ens3` | `10.10.10.10/24` | route to client LAN via `10.10.10.1` |
| WAF/Zorin backend | `ens4` | `10.10.20.10/24` | no default gateway |
| WAF/Zorin management | `ens5` | `172.16.42.150/24` | optional Internet route via EVE-NG host |
| DVWA backend | `ens3` | `10.10.20.20/24` | `10.10.20.10` |
| DVWA management | `ens4` | `172.16.42.157/24` | optional Internet route via EVE-NG host |

## Service ports

| Service | Host | Port | Exposure |
|---|---|---:|---|
| C WAF engine | WAF/Zorin | `3333` | exposed to Kali through pfSense |
| PHP dashboard | WAF/Zorin | `8081` | local-only on `localhost` |
| DVWA | DVWA Ubuntu Server | `8000` | reachable from WAF backend only |

## Why the dashboard is local-only

The PHP dashboard is an admin/control interface, so it is not exposed on `10.10.10.10`. It is started with:

```bash
php -S localhost:8081 -t dashboard/public
```

That means it can be opened only on the Zorin browser using:

```text
http://localhost:8081
```

Kali should interact with the WAF engine only, not with the dashboard.
