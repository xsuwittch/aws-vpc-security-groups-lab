# AWS VPC Security Groups - Hands-On Lab

**Author:** Muhammad Ammar Rana ([@xsuwittch](https://github.com/xsuwittch))  
**Date:** June 2026  
**Region:** ap-south-1 (Mumbai)  
**Cert Track:** SAA-C03 / SCS-C03 Prep

---

## What This Is

I got tired of just reading about security groups so I decided to actually build something and prove the concepts with real traffic and real logs. This lab covers SG-to-SG referencing, stateful behavior, and defence in depth. Everything here is verified through VPC Flow Logs, not just assumed to work.

---

## Architecture

```
Internet
    |
    v
+-------------------------------------+
|           Public Subnet             |
|                                     |
|   +----------+    +--------------+  |
|   |  jammie  |    |   cersei     |  |
|   | (bastion)|    | (public inst)|  |
|   +----------+    +--------------+  |
+-------------------------------------+
          |
          v
+-------------------------------------+
|           Private Subnet            |
|                                     |
|          +----------+               |
|          |  tyrion  |               |
|          | (private)|               |
|          +----------+               |
+-------------------------------------+
```

Named after Game of Thrones characters because why not.

| Name | Subnet | Role |
|------|--------|------|
| jammie | Public | Bastion. Only entry point into the setup |
| cersei | Public | Public instance. Not directly reachable, only through jammie |
| tyrion | Private | Private instance. No public IP, only reachable through jammie |

All three use the same key pair: `tywin.pem`

---

## Security Group Setup

The main thing I wanted to test here was SG-to-SG referencing. Instead of putting an IP address as the source of a rule, you put a security group ID. AWS then checks whether the connecting instance has that SG attached, not where its IP is coming from. Works like a badge system basically.

**jammie's SG (`sg-07bc69639c7fd90aa`) - "Jammie, a good brother"**

| Direction | Protocol | Port | Source |
|-----------|----------|------|--------|
| Inbound | SSH | 22 | 0.0.0.0/0 |

Jammie is the bastion so it needs to be reachable from the internet. Not ideal but acceptable since home IPs are dynamic.

**cersei's SG**

| Direction | Protocol | Port | Source |
|-----------|----------|------|--------|
| Inbound | SSH | 22 | sg-07bc69639c7fd90aa |

Only instances carrying jammie's SG can SSH in. Everything else gets blocked.

**tyrion's SG**

| Direction | Protocol | Port | Source |
|-----------|----------|------|--------|
| Inbound | SSH | 22 | sg-07bc69639c7fd90aa |

Same as cersei. Only jammie gets through.

**Access matrix:**

```
Laptop  -> jammie   OK  (public bastion, open to internet)
jammie  -> cersei   OK  (jammie's SG is trusted by cersei)
jammie  -> tyrion   OK  (jammie's SG is trusted by tyrion)
cersei  -> tyrion   BLOCKED  (cersei's SG is not in tyrion's rules)
Laptop  -> cersei   BLOCKED  (not coming from jammie's SG)
Laptop  -> tyrion   BLOCKED  (private subnet + SG, double blocked)
```

Cersei and Tyrion literally cannot talk to each other. Fitting.

---

## Concepts Tested

### Default Deny

Security groups block everything by default. No rules = no access. Tested this by trying to SSH directly into cersei from my laptop. Connection timed out immediately, nothing reached the instance.

### SG-to-SG Referencing

This is the right way to do multi-tier networking on AWS. Using IP addresses as sources is fragile because IPs change. Using SG IDs means the rule stays valid regardless of IP changes, and any new instance you spin up with the right SG automatically gets access without touching the rules.

### Stateful Behavior

Security groups track connection state. Once a connection is allowed in one direction, the return traffic gets through automatically. You don't need a separate outbound rule for responses.

```
You -> SSH -> jammie     [inbound rule allows port 22]
You <- jammie            [no outbound rule, but response gets through automatically]
```

This is different from NACLs which are stateless and evaluate every single packet independently in both directions.

### Defence in Depth

Tyrion has two independent layers of protection. Private subnet means there's no route from the internet to get to it in the first place. The SG is a second layer on top of that so even if the routing was somehow misconfigured, the SG would still block anything that isn't coming from jammie. Both have to fail for someone to get in.

---

## SSH Commands

Getting to tyrion requires two hops since it's in a private subnet with no public IP.

```bash
# hop 1 - get into the bastion
ssh -i "tywin.pem" ubuntu@<jammie-public-ip>

# hop 2 - from inside jammie, reach tyrion using its private IP
ssh -i "tywin.pem" ubuntu@<tyrion-private-ip>
```

Always use private IPs when you're already inside the VPC. Using public IPs routes traffic out to the internet and back in which costs money and makes no sense when you're already on the same internal network.

**Copying the key to another instance:**

```bash
# copy key from your machine to jammie
scp -i "tywin.pem" tywin.pem ubuntu@<jammie-public-ip>:~/.ssh/

# or skip the middle step using ProxyJump
scp -i "tywin.pem" -o ProxyJump=ubuntu@<jammie-public-ip> tywin.pem ubuntu@<cersei-private-ip>:~/.ssh/
```

---

## VPC Flow Logs - Proof

Enabled flow logs on the VPC with a 1-minute aggregation interval, sending to CloudWatch Logs. This captures every accepted and rejected connection with the source IP, destination IP, port, and decision.

**Flow log format:**
```
version | account-id | eni-id | src-ip | dst-ip | src-port | dst-port | protocol | packets | bytes | start | end | action | status
```

**Direct SSH from my laptop to cersei - REJECTED**
```
154.192.43.167 -> 10.0.5.109  port 22  REJECT
```
My public IP trying to hit cersei directly. Blocked because cersei only trusts jammie's SG.

**Jammie SSHing into cersei - ACCEPTED**
```
10.0.7.15 -> 10.0.5.109  port 22  ACCEPT
10.0.5.109 -> 10.0.7.15  port 22  ACCEPT
```
Both directions show up as ACCEPT. The second line is the response traffic being automatically allowed back. That's stateful behavior in the logs.

**Jammie SSHing into tyrion - ACCEPTED**
```
10.0.7.15 -> 10.0.138.37  port 22  ACCEPT
10.0.138.37 -> 10.0.7.15  port 22  ACCEPT
```
Same result. Jammie's SG is trusted, connection goes through.

**Cersei trying to SSH into tyrion - REJECTED**
```
10.0.5.109 -> 10.0.138.37  port 22  REJECT
```
Cersei and Tyrion are in the same VPC but cersei's SG isn't in tyrion's rules. Blocked.

### Bots

The moment an EC2 instance gets a public IP, automated scanners start hitting it. Within minutes of launching cersei I was already seeing this in the logs:

```
162.216.149.88  -> 10.0.5.109  port 9881   REJECT
165.154.206.151 -> 10.0.5.109  port 22735  REJECT
204.76.203.51   -> 10.0.5.109  port 8900   REJECT
216.180.246.40  -> 10.0.5.109  port 8080   REJECT
```

These are tools like Shodan and Censys scanning the entire internet constantly. Your instance gets a public IP and it immediately shows up on their radar. All of these got blocked by the SG. This is also why you never open port 22 to 0.0.0.0/0 on anything except a bastion - SSH scanners will find it and start brute forcing.

---

## Cost

- EC2 instances: t3.micro / t3.small (free tier eligible)
- VPC Flow Logs: free to create, CloudWatch ingestion was fractions of a cent for the lab
- VPC internal traffic using private IPs: free

Disable flow logs after you're done to avoid ongoing CloudWatch costs.

---

## What's Next

This is just the bastion layer. The full 3-tier architecture I'm building adds:

- Load Balancer in the public subnet, accepting HTTPS from the internet
- App server in a private subnet, only accepting traffic from the LB's SG
- RDS in an isolated private subnet, only accepting traffic from the app server's SG

Each tier only trusts the SG directly above it. No lateral movement possible between tiers.

---

## References

- [AWS Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html)
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [Security Groups vs NACLs](https://docs.aws.amazon.com/vpc/latest/userguide/infrastructure-security.html)
