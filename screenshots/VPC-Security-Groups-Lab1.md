# AWS VPC Security Groups — Hands-On Lab
> **Author:** Muhammad Ammar Rana ([@xsuwittch](https://github.com/xsuwittch))  
> **Date:** June 2026  
> **Region:** ap-south-1 (Mumbai)  
> **Cert Track:** SAA-C03 / SCS-C03 Prep

---

## Overview

This lab demonstrates AWS Security Groups in practice — not just theory. By the end you will have:

- Built a multi-instance VPC with public and private subnets
- Configured security groups using SG-to-SG referencing (not IP-based rules)
- Proved stateful behavior through live traffic testing
- Observed real rejected and accepted connections in VPC Flow Logs

---

## Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────┐
│           Public Subnet             │
│                                     │
│   ┌──────────┐    ┌──────────────┐  │
│   │  jammie  │    │   cersei     │  │
│   │ (bastion)│    │ (public inst)│  │
│   └──────────┘    └──────────────┘  │
└─────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────┐
│           Private Subnet            │
│                                     │
│          ┌──────────┐               │
│          │  tyrion  │               │
│          │ (private)│               │
│          └──────────┘               │
└─────────────────────────────────────┘
```

### Instances

| Name | Subnet | Role | Key |
|------|--------|------|-----|
| jammie | Public | Bastion host — single entry point | tywin.pem |
| cersei | Public | Public instance — only reachable via jammie | tywin.pem |
| tyrion | Private | Private instance — only reachable via jammie | tywin.pem |

---

## Security Group Design

### The Core Principle

Instead of hardcoding IP addresses, security group IDs are used as sources. This means:

- AWS checks whether the **connecting instance has a specific SG attached**, not what its IP is
- If an instance's IP changes, the rule still works
- Auto-scales — any new instance with the right SG automatically gets access

### SG Rules

**jammie's SG (`sg-07bc69639c7fd90aa`) — "Jammie, a good brother"**

| Direction | Protocol | Port | Source | Purpose |
|-----------|----------|------|--------|---------|
| Inbound | TCP (SSH) | 22 | 0.0.0.0/0 | Allow SSH from internet (bastion) |

**cersei's SG**

| Direction | Protocol | Port | Source | Purpose |
|-----------|----------|------|--------|---------|
| Inbound | TCP (SSH) | 22 | sg-07bc69639c7fd90aa (jammie) | Only jammie can SSH in |

**tyrion's SG**

| Direction | Protocol | Port | Source | Purpose |
|-----------|----------|------|--------|---------|
| Inbound | TCP (SSH) | 22 | sg-07bc69639c7fd90aa (jammie) | Only jammie can SSH in |

### Access Matrix

```
Your Laptop  ──SSH──►  jammie   ✅ (public bastion)
jammie       ──SSH──►  cersei   ✅ (jammie's SG is trusted)
jammie       ──SSH──►  tyrion   ✅ (jammie's SG is trusted)
cersei       ──SSH──►  tyrion   ❌ (cersei's SG is not trusted by tyrion)
Your Laptop  ──SSH──►  cersei   ❌ (cersei not reachable directly)
Your Laptop  ──SSH──►  tyrion   ❌ (private subnet + SG blocks it)
```

---

## Key Concepts Demonstrated

### 1. Default Deny

Every security group denies all traffic by default. Nothing reaches an instance unless explicitly allowed. Proved by attempting direct SSH to cersei from the internet — connection timed out immediately.

### 2. SG-to-SG Referencing

Using a security group ID as the source of a rule instead of an IP address. Think of it as a **badge system** — only instances wearing the right badge get through, regardless of their IP.

### 3. Stateful Behavior

Security groups track connection state. Once a connection is approved in one direction, return traffic is automatically allowed — no explicit rule needed.

```
You ──SSH──► jammie       [inbound rule: port 22 ✅]
You ◄──────── jammie       [no outbound rule needed — return traffic auto-allowed]
```

This is the key difference from NACLs which are stateless and require explicit rules for both directions.

### 4. Defence in Depth

tyrion is protected by two independent layers:
- **Layer 1:** Private subnet — no route to the internet, no public IP
- **Layer 2:** Security group — only accepts SSH from jammie's SG

If one layer is misconfigured, the other still holds.

---

## SSH Flow

### Reaching tyrion (two hops)

```bash
# Step 1 — SSH into bastion from your machine
ssh -i "tywin.pem" ubuntu@<jammie-public-ip>

# Step 2 — From inside jammie, SSH into tyrion using private IP
ssh -i "tywin.pem" ubuntu@<tyrion-private-ip>
```

### Copy key to intermediary instance

```bash
# From your machine — copy key to jammie first
scp -i "tywin.pem" tywin.pem ubuntu@<jammie-public-ip>:~/.ssh/

# Or one-liner via ProxyJump directly to cersei
scp -i "tywin.pem" -o ProxyJump=ubuntu@<jammie-public-ip> tywin.pem ubuntu@<cersei-private-ip>:~/.ssh/
```

---

## VPC Flow Logs — Proof

Flow logs were enabled on the VPC (1-minute aggregation interval, CloudWatch Logs destination) to capture and verify all traffic decisions.

### Flow Log Format

```
version | account-id | eni-id | src-ip | dst-ip | src-port | dst-port | protocol | packets | bytes | start | end | action | status
```

### What the Logs Showed

**Direct SSH attempt from laptop to cersei — REJECTED**
```
154.192.43.167 → 10.0.5.109  port 22  REJECT
```
Laptop's public IP hitting cersei directly. Blocked — cersei's SG only trusts jammie's SG, not random IPs.

**jammie SSHing into cersei — ACCEPTED (both directions)**
```
10.0.7.15 → 10.0.5.109  port 22  ACCEPT   ← request
10.0.5.109 → 10.0.7.15  port 22  ACCEPT   ← response (stateful — auto-allowed)
```
jammie's private IP (`10.0.7.15`) to cersei's private IP (`10.0.5.109`). Accepted because jammie carries the trusted SG. Both directions logged — proving stateful behavior.

**jammie SSHing into tyrion — ACCEPTED**
```
10.0.7.15 → 10.0.138.37  port 22  ACCEPT
10.0.138.37 → 10.0.7.15  port 22  ACCEPT
```
Same pattern — jammie trusted, connection succeeds.

**cersei attempting to SSH into tyrion — REJECTED**
```
10.0.5.109 → 10.0.138.37  port 22  REJECT
```
cersei's SG is not in tyrion's trusted sources. Blocked at the SG level even though both instances are in the same VPC.

### Internet Background Noise

Within minutes of launching instances with public IPs, automated scanners from across the internet started probing random ports:

```
162.216.149.88  → 10.0.5.109  port 9881   REJECT
165.154.206.151 → 10.0.5.109  port 22735  REJECT
204.76.203.51   → 10.0.5.109  port 8900   REJECT
216.180.246.40  → 10.0.5.109  port 8080   REJECT
```

These are Shodan, Censys, and botnet scanners hitting every public IP on the internet. All blocked by the security group. This is why default deny exists.

---

## Lessons Learned

**Security groups are identity-based, not IP-based.** Using SG IDs as sources is cleaner, more scalable, and more resilient than IP rules.

**Private IPs inside VPC, public IPs for external access.** Traffic between instances in the same VPC should always use private IPs — it stays on the internal network, costs nothing, and doesn't route through the internet gateway.

**Flow logs are essential for verification.** You can't trust that rules are working without checking the logs. This is also how SOC analysts detect intrusion attempts in production.

**Bots are instant.** A public IP is scanned within minutes of assignment. Security groups are not optional.

**Defence in depth works.** tyrion has no public IP and a restrictive SG. Two independent controls — both have to fail for an attacker to get in.

---

## Cost Notes

- EC2 instances: t3.micro / t3.small (free tier eligible)
- VPC Flow Logs: free to create, CloudWatch ingestion costs fractions of a cent for a short lab
- Data transfer within VPC using private IPs: free

**Remember to disable flow logs after the lab to avoid ongoing CloudWatch costs.**

---

## What's Next

This lab covers the bastion layer only. The full 3-tier architecture will add:

- **Load Balancer** (public subnet) — accepts traffic from internet on 443
- **Web/App Server** (private subnet) — only accepts traffic from LB's SG
- **RDS Database** (isolated private subnet) — only accepts traffic from app server's SG

Each tier only trusts the SG directly above it in the chain. Zero lateral movement possible.

---

## References

- [AWS Security Groups Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html)
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [Security Group vs NACL](https://docs.aws.amazon.com/vpc/latest/userguide/infrastructure-security.html)
