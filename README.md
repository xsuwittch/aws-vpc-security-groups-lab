# AWS VPC Security Groups 

**Author:** Muhammad Ammar Rana ([@xsuwittch](https://github.com/xsuwittch))
**Date:** June 2026 | **Region:** ap-south-1 (Mumbai)

---

## Why I Built This

Reading about security groups is one thing. Actually watching a REJECT hit the logs the moment you break a rule is different. I wanted to prove the concepts of SG-to-SG referencing, stateful behavior, defence in depth with real traffic and real evidence as practicle works help me understand concept better then any theory could.

Everything in this writeup is verified through VPC Flow Logs.

---

## Architecture

```
Internet
    |
    v
+-------------------------------------+
|           Public Subnet             |
|   +----------+    +--------------+  |
|   |  jammie  |    |   cersei     |  |
|   | (bastion)|    | (public inst)|  |
|   +----------+    +--------------+  |
+-------------------------------------+
          |
          v
+-------------------------------------+
|           Private Subnet            |
|          +----------+               |
|          |  tyrion  |               |
|          | (private)|               |
|          +----------+               |
+-------------------------------------+
```

| Instance | Subnet | Role |
|----------|--------|------|
| jammie | Public | Bastion, the only entry point into the environment |
| cersei | Public | Public instance,  not directly reachable, only through jammie |
| tyrion | Private | Private instance, no public IP, only reachable through jammie |

Named after GoT characters. Cersei and Tyrion can't talk to each other. Fitting.

---

## Security Design

### The Problem with IP-Based Rules

Most people configure security groups with IP addresses as sources. That breaks the moment an IP changes auto scaled instance, new deployment, anything. It also doesn't scale.

The right approach is SG-to-SG referencing. Instead of trusting an IP, you trust a security group ID. AWS checks whether the connecting instance is wearing that badge, regardless of where its IP comes from. New instance with the right SG attached? It automatically gets access without touching a single rule.

### Security Group Configuration

**jammie's SG (`sg-07bc69639c7fd90aa`) — "Jammie, a good brother"**

| Direction | Protocol | Port | Source |
|-----------|----------|------|--------|
| Inbound | SSH | 22 | 0.0.0.0/0 |

Bastion needs to be reachable from the internet. Not ideal but acceptable here since home IPs are dynamic. In production this would be locked to a corporate IP range or behind a VPN.

**cersei's SG**

| Direction | Protocol | Port | Source |
|-----------|----------|------|--------|
| Inbound | SSH | 22 | sg-07bc69639c7fd90aa |

Only instances carrying jammie's SG can get in. An IP hitting cersei directly gets dropped before the connection even establishes.

**tyrion's SG**

| Direction | Protocol | Port | Source |
|-----------|----------|------|--------|
| Inbound | SSH | 22 | sg-07bc69639c7fd90aa |

Same rule. Only jammie gets through. cersei and tyrion are in the same VPC but cannot talk to each other cersei's SG isn't in tyrion's trust list.

### Access Matrix

```
Laptop  ->  jammie   ALLOW   public bastion, open to internet
jammie  ->  cersei   ALLOW   jammie's SG is trusted by cersei
jammie  ->  tyrion   ALLOW   jammie's SG is trusted by tyrion
cersei  ->  tyrion   BLOCK   cersei's SG is not in tyrion's rules
Laptop  ->  cersei   BLOCK   cersei only trusts jammie's SG
Laptop  ->  tyrion   BLOCK   private subnet + SG, two independent blocks
```

---

## Threat Model

What does this design actually protect against?

**Lateral movement** if cersei is compromised, the attacker is stuck. They can't pivot to tyrion because cersei's SG isn't trusted. Compromising one instance doesn't give you the rest of the environment.

**Direct internet exposure** tyrion has no public IP and lives in a private subnet with no internet gateway route. Even if someone somehow bypassed the SG, the routing doesn't exist to get there from the internet.

**Credential reuse attacks** the bastion pattern means SSH keys only need to be valid on one public-facing instance. Everything behind it is isolated.

**Shodan/scanner exposure** public instances will get found and probed within minutes of launch (more on this below). SGs block everything that isn't explicitly allowed, so scanners see a closed surface.

---

## Defence in Depth on tyrion

tyrion has two completely independent security controls:

- **Private subnet**  no route from the internet, no public IP, unreachable at the network layer
- **Security group**  even if routing was somehow misconfigured, the SG still rejects anything not coming from jammie's SG

Both have to fail simultaneously for an attacker to reach tyrion. This is what defence in depth actually means in practice not just having multiple tools, but having multiple independent controls where breaking one doesn't break the others.

---

## VPC Flow Logs  Proof

Enabled flow logs on the VPC with 1-minute aggregation, sending to CloudWatch Logs. Every connection attempt accepted or rejected shows up with source IP, destination IP, port, and decision.

Flow log format:
```
version | account-id | eni-id | src-ip | dst-ip | src-port | dst-port | protocol | packets | bytes | start | end | action | status
```

### Laptop hitting cersei directly REJECTED

```
154.192.43.167 -> 10.0.5.109  port 22  REJECT
```

My public IP trying to SSH directly into cersei. Blocked immediately  cersei doesn't trust random IPs, only jammie's SG.

### jammie SSHing into cersei  ACCEPTED (both directions)

```
10.0.7.15 -> 10.0.5.109  port 22  ACCEPT
10.0.5.109 -> 10.0.7.15  port 22  ACCEPT
```

jammie's private IP to cersei's private IP, both logged as ACCEPT. The second line is the return traffic being automatically allowed back through. That's stateful behavior  the SG tracks the connection and permits the response without needing a separate outbound rule.

### jammie SSHing into tyrion  ACCEPTED

```
10.0.7.15 -> 10.0.138.37  port 22  ACCEPT
10.0.138.37 -> 10.0.7.15  port 22  ACCEPT
```

Same pattern. jammie is trusted, connection goes through, stateful return traffic logged.

### cersei attempting to SSH into tyrion  REJECTED

```
10.0.5.109 -> 10.0.138.37  port 22  REJECT
```

cersei and tyrion are in the same VPC. Same account, same region, adjacent subnets. Still blocked. cersei's SG isn't in tyrion's trust list the SG doesn't care about network proximity, only about identity.

---

## Internet Background Noise

Within minutes of launching cersei and assigning it a public IP, the logs started filling up with this:

```
162.216.149.88  -> 10.0.5.109  port 9881   REJECT
165.154.206.151 -> 10.0.5.109  port 22735  REJECT
204.76.203.51   -> 10.0.5.109  port 8900   REJECT
216.180.246.40  -> 10.0.5.109  port 8080   REJECT
```

Shodan, Censys, and various botnet scanners continuously sweep the entire IPv4 space. The moment your instance gets a public IP it's on their radar. All of these were blocked by the security group. This is also why you never expose SSH to 0.0.0.0/0 on anything except a dedicated bastion — scanners find open port 22s and start brute forcing them immediately.

The logs make this visible in a way that just reading about it doesn't.

---

## SSH Flow

Getting to tyrion requires two hops since it has no public IP.

```bash
# hop 1 — into the bastion
ssh -i "tywin.pem" ubuntu@<jammie-public-ip>

# hop 2 — from inside jammie, reach tyrion by private IP
ssh -i "tywin.pem" ubuntu@<tyrion-private-ip>
```

Always use private IPs for traffic inside the VPC. Using public IPs routes traffic out through the internet gateway and back in — costs money, adds latency, and makes no sense when you're already on the internal network.

```bash
# copy key to jammie first
scp -i "tywin.pem" tywin.pem ubuntu@<jammie-public-ip>:~/.ssh/

# or skip the middle step with ProxyJump
scp -i "tywin.pem" -o ProxyJump=ubuntu@<jammie-public-ip> tywin.pem ubuntu@<cersei-private-ip>:~/.ssh/
```

---

## Key Takeaways

**SG-to-SG referencing is the correct pattern for multi-tier AWS architecture.** IP-based rules are fragile and don't scale. Identity-based rules do.

**Stateful vs stateless matters operationally.** Security groups track connection state and auto-allow return traffic. NACLs don't  they evaluate every packet independently in both directions. Confusing the two leads to broken rules that are hard to debug.

**Flow logs are not optional for verification.** You cannot trust that a security rule is working without checking the logs. This is also exactly what SOC analysts look at when investigating lateral movement attempts in production the same ACCEPT/REJECT patterns at scale.

**Default deny is your baseline, not your backup.** Nothing reaches an instance unless explicitly permitted. The internet will start probing your public IPs within minutes. Let the logs show you what's being blocked.

---

## Cost

- EC2: t3.micro / t3.small (free tier eligible)
- VPC Flow Logs: free to enable, CloudWatch ingestion was fractions of a cent for this lab
- Internal VPC traffic on private IPs: free

Disable flow logs when the lab is done to avoid ongoing CloudWatch charges.

---

## What's Next

This covers the bastion and SG layer. The full 3-tier architecture adds:

- **Load Balancer** in the public subnet — accepts HTTPS from internet, nothing else
- **App server** in a private subnet — only accepts traffic from the LB's SG
- **RDS** in an isolated private subnet — only accepts traffic from the app server's SG

Each tier trusts only the SG directly above it. No lateral movement possible between tiers. If any one tier is compromised, the blast radius is contained.

---

## References

- [AWS Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html)
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [Security Groups vs NACLs](https://docs.aws.amazon.com/vpc/latest/userguide/infrastructure-security.html)
