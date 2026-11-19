# Detection Rules

<!-- Generated from backend/detection-service/src/main/resources/detection-rules.json; regenerate when rules change. -->

The detection service ships 18 rules. `SIEM-1001`–`SIEM-1007` are the original v1 rules; a test (`RuleCatalogueTest.legacyRulesMatchExactlyAsTheV1EngineDid`) proves they still decide exactly as v1 did on every event type × severity combination.

## Rule types

| Type | Fires when |
|---|---|
| `SINGLE` | One event satisfies the condition. Alert ID = hash(rule, event), so Kafka redelivery never duplicates an alert. |
| `THRESHOLD` | Within a sliding window, events grouped by `groupBy` reach a count, a number of distinct values, a summed attribute, or (with `maxJitterRatio`) a periodic cadence. |
| `SEQUENCE` | Steps occur in order for the same group within the window (e.g. failures *then* a success). |

Every alert records **evidence**: the matched clauses, group key, window, first/last seen, and up to 50 contributing event IDs. The console shows this as *Why this alert fired*.

## Guarantees and limits

- **Versioned.** Each rule has a `version`; every alert stores the version that produced it. Runtime changes (enable/disable/severity) bump the version and are recorded in `GET /api/rules/{id}/history` and the audit log.
- **Tested.** Each rule ships `match` and `noMatch` examples. `RuleCatalogueTest` replays them on every build: `match` must fire exactly once and `noMatch` never. Rules without false-positive notes, a valid ATT&CK ID, or examples fail the build.
- **Bounded state.** Correlation state is capped at 10,000 groups per rule and 1,000 events per group (least-recently-used eviction). Disabling a rule clears its state.
- **Single instance.** Correlation state lives in memory, so threshold and sequence rules are exact only with one detection instance (or with events partitioned by the grouping key). State is lost on restart, which can delay, but never duplicate, an alert.

## Testing a rule

`POST /api/rules/test` (analysts and above) replays up to 500 events through one rule in an isolated engine. Nothing is published, stored or alerted. Omit `events` to verify the rule's packaged examples. The **Detection Rules** page has a UI for this.

```bash
curl -s -X POST "$GATEWAY/api/rules/test" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ruleId":"SIEM-1010","events":[{"eventType":"POWERSHELL","severity":"MEDIUM","message":"powershell.exe -enc SQBFAFgA"}]}'
```

## Catalogue

| ID | v | Name | Type | Severity | ATT&CK |
|---|---|---|---|---|---|
| `SIEM-1001` | 1 | Critical Malware Detected | SINGLE | CRITICAL | [T1204](https://attack.mitre.org/techniques/T1204/) User Execution, [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact |
| `SIEM-1002` | 1 | Repeated Login Failures | SINGLE | HIGH | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force |
| `SIEM-1003` | 1 | Privilege Escalation Attempt | SINGLE | CRITICAL | [T1068](https://attack.mitre.org/techniques/T1068/) Exploitation for Privilege Escalation, [T1090.003](https://attack.mitre.org/techniques/T1090/003/) Proxy: Multi-hop Proxy |
| `SIEM-1004` | 1 | Network Reconnaissance Activity | SINGLE | MEDIUM | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery |
| `SIEM-1005` | 1 | Data Exfiltration Attempt | SINGLE | CRITICAL | [T1041](https://attack.mitre.org/techniques/T1041/) Exfiltration Over C2 Channel |
| `SIEM-1006` | 1 | Suspicious Activity on Sensitive Asset | SINGLE | CRITICAL | — |
| `SIEM-1007` | 1 | Command Shell or Payload Activity | SINGLE | HIGH | [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter, [T1071](https://attack.mitre.org/techniques/T1071/) Application Layer Protocol, [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Server Software Component: Web Shell |
| `SIEM-1008` | 1 | Brute Force: Repeated Authentication Failures | THRESHOLD | HIGH | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing |
| `SIEM-1009` | 1 | Successful Login After Repeated Failures | SEQUENCE | CRITICAL | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force, [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts |
| `SIEM-1010` | 1 | Suspicious PowerShell Execution | SINGLE | HIGH | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell, [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information |
| `SIEM-1011` | 1 | Network Port Scan | THRESHOLD | MEDIUM | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery |
| `SIEM-1012` | 1 | Large Outbound Transfer to External Host | THRESHOLD | HIGH | [T1048](https://attack.mitre.org/techniques/T1048/) Exfiltration Over Alternative Protocol, [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service |
| `SIEM-1013` | 1 | Command-and-Control Beaconing | THRESHOLD | HIGH | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Application Layer Protocol: Web Protocols, [T1573](https://attack.mitre.org/techniques/T1573/) Encrypted Channel |
| `SIEM-1014` | 1 | Outbound Connection on Uncommon Port | SINGLE | MEDIUM | [T1571](https://attack.mitre.org/techniques/T1571/) Non-Standard Port |
| `SIEM-1015` | 1 | Known Malware Test Indicator (EICAR) | SINGLE | HIGH | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File |
| `SIEM-1016` | 1 | Security Audit Log Cleared | SINGLE | HIGH | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs |
| `SIEM-1017` | 1 | Account Added to Privileged Group | SINGLE | HIGH | [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation, [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation |
| `SIEM-1018` | 1 | Burst of Administrative Changes | THRESHOLD | MEDIUM | [T1136](https://attack.mitre.org/techniques/T1136/) Create Account, [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation |


### SIEM-1001 · Critical Malware Detected

Endpoint protection reported a malware or ransomware detection.

**Logic**

- eventType ∈ {MALWARE_DETECTED, RANSOMWARE_ACTIVITY, RANSOMWARE}
- severity ≥ HIGH

**ATT&CK:** Execution: T1204 User Execution; Impact: T1486 Data Encrypted for Impact

**False positives**

- EDR test detections (e.g. EICAR) run by the security team
- Quarantined files re-scanned after restore

### SIEM-1002 · Repeated Login Failures

High-severity authentication failures indicate a brute-force attempt.

**Logic**

- eventType ∈ {LOGIN_FAILURE}
- severity ≥ HIGH

**ATT&CK:** Credential Access: T1110 Brute Force

**False positives**

- Source systems that already aggregate failures and emit one HIGH event for a locked account
- See SIEM-1008 for the volume-based variant

### SIEM-1003 · Privilege Escalation Attempt

A privilege escalation or unauthorized elevation attempt was observed.

**Logic**

- eventType ∈ {PRIVILEGE_ESCALATION, TOR_UNKNOWN}
- severity ≥ HIGH

**ATT&CK:** Privilege Escalation: T1068 Exploitation for Privilege Escalation; Command and Control: T1090.003 Proxy: Multi-hop Proxy

**False positives**

- Approved admin elevation (sudo/runas) misreported as escalation by the source
- TOR_UNKNOWN is grouped here for backwards compatibility; it indicates anonymised access rather than elevation

### SIEM-1004 · Network Reconnaissance Activity

Port scans or network reconnaissance patterns from a host.

**Logic**

- eventType ∈ {PORT_SCAN, SCAN}
- severity ≥ MEDIUM

**ATT&CK:** Discovery: T1046 Network Service Discovery

**False positives**

- Authorised vulnerability scanners (allow-list their source IPs)
- Network monitoring tools

### SIEM-1005 · Data Exfiltration Attempt

Suspected exfiltration of data from the environment.

**Logic**

- eventType ∈ {DATA_EXFILTRATION}

**ATT&CK:** Exfiltration: T1041 Exfiltration Over C2 Channel

**False positives**

- DLP policies that flag sanctioned transfers to partners

### SIEM-1006 · Suspicious Activity on Sensitive Asset

Any critical event regardless of type requires immediate attention.

**Logic**

- severity ≥ CRITICAL

**False positives**

- Sources that over-grade routine events as CRITICAL; this rule overlaps with type-specific rules by design

### SIEM-1007 · Command Shell or Payload Activity

Command-and-control or payload delivery indicators observed.

**Logic**

- eventType ∈ {COMMAND_SHELL, POWERSHELL, C2_BEACON, WEBSHELL}

**ATT&CK:** Execution: T1059 Command and Scripting Interpreter; Command and Control: T1071 Application Layer Protocol; Persistence: T1505.003 Server Software Component: Web Shell

**False positives**

- Administrators using interactive shells on servers
- Sources that report every PowerShell launch

### SIEM-1008 · Brute Force: Repeated Authentication Failures

Five or more failed logins from one source IP within five minutes, regardless of how each event is graded.

**Logic**

- eventType ∈ {LOGIN_FAILURE}
- count ≥ 5 per sourceIp within 300s
- repeat alerts for the same group suppressed for 900s

**ATT&CK:** Credential Access: T1110.001 Brute Force: Password Guessing

**False positives**

- Service accounts retrying a stale password after rotation
- Many users behind one NAT/VPN egress IP

### SIEM-1009 · Successful Login After Repeated Failures

Three or more failed logins for an account followed by a successful login within ten minutes: a possible successful brute force.

**Logic**

- in order per userName within 600s: failures (eventType ∈ {LOGIN_FAILURE}) ×3 → success (eventType ∈ {LOGIN_SUCCESS})
- repeat alerts for the same group suppressed for 1800s

**ATT&CK:** Credential Access: T1110 Brute Force; Initial Access: T1078 Valid Accounts

**False positives**

- A user mistyping their password a few times before succeeding (tune minCount for your environment)

### SIEM-1010 · Suspicious PowerShell Execution

PowerShell run with encoded commands, download cradles or in-memory execution.

**Logic**

- eventType ∈ {POWERSHELL, PROCESS_CREATE}
- message contains any of `-encodedcommand`, `-enc `, `frombase64string`, `iex(`, `iex (`, `invoke-expression`, `downloadstring`, `downloadfile`, `-windowstyle hidden`, `-w hidden`, `-executionpolicy bypass`, `-ep bypass`

**ATT&CK:** Execution: T1059.001 Command and Scripting Interpreter: PowerShell; Defense Evasion: T1027 Obfuscated Files or Information

**False positives**

- Management tooling (SCCM, Intune, RMM agents) that legitimately uses -EncodedCommand
- Admin scripts launched with -ExecutionPolicy Bypass

### SIEM-1011 · Network Port Scan

One source contacted 15 or more distinct destination ports within 60 seconds.

**Logic**

- eventType ∈ {CONNECTION_ATTEMPT, FIREWALL_DENY, NETWORK_CONNECTION}
- distinct destinationPort ≥ 15 per sourceIp within 60s
- repeat alerts for the same group suppressed for 600s

**ATT&CK:** Discovery: T1046 Network Service Discovery

**False positives**

- Authorised vulnerability scanners
- Service discovery or monitoring agents

### SIEM-1012 · Large Outbound Transfer to External Host

More than 500 MB sent from one internal host to one external destination within an hour.

**Logic**

- eventType ∈ {NETWORK_FLOW, OUTBOUND_TRANSFER}
- destination is a public IP
- sum(bytesOut) ≥ 500000000 per sourceIp+destinationIp within 3600s
- repeat alerts for the same group suppressed for 3600s

**ATT&CK:** Exfiltration: T1048 Exfiltration Over Alternative Protocol; Exfiltration: T1567 Exfiltration Over Web Service

**False positives**

- Backups or sync to sanctioned cloud storage
- Large legitimate uploads (media, datasets)

### SIEM-1013 · Command-and-Control Beaconing

Eight or more connections from one host to one external destination at regular intervals within an hour.

**Logic**

- eventType ∈ {NETWORK_CONNECTION, OUTBOUND_CONNECTION, HTTP_REQUEST}
- destination is a public IP
- count ≥ 8 per sourceIp+destinationIp within 3600s
- inter-arrival jitter ≤ 15% (periodic)
- repeat alerts for the same group suppressed for 3600s

**ATT&CK:** Command and Control: T1071.001 Application Layer Protocol: Web Protocols; Command and Control: T1573 Encrypted Channel

**False positives**

- Software update checks, telemetry and heartbeats (allow-list known vendor destinations)
- NTP and monitoring polls

### SIEM-1014 · Outbound Connection on Uncommon Port

Internal host connected to an external address on a port commonly used by remote-access tools and C2 frameworks.

**Logic**

- eventType ∈ {NETWORK_CONNECTION, OUTBOUND_CONNECTION}
- destinationPort ∈ {1337, 4444, 5555, 6667, 8888, 9001, 31337}
- destination is a public IP

**ATT&CK:** Command and Control: T1571 Non-Standard Port

**False positives**

- Developer tools or games using these ports
- IRC (6667) where permitted

### SIEM-1015 · Known Malware Test Indicator (EICAR)

A file matching the EICAR anti-malware test file hash was observed. EICAR is harmless and used to verify that detection works end to end.

**Logic**

- eventType ∈ {FILE_CREATED, FILE_HASH_OBSERVED, PROCESS_CREATE}
- fileHash ∈ {44d88612fea8a8f36de82e1278abb02f, 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f}

**ATT&CK:** Execution: T1204.002 User Execution: Malicious File

**False positives**

- Deliberate EICAR tests by the security team (that is the point of this rule)

### SIEM-1016 · Security Audit Log Cleared

A security or audit log was cleared, a common anti-forensics step.

**Logic**

- eventType ∈ {AUDIT_LOG_CLEARED, LOG_CLEARED}

**ATT&CK:** Defense Evasion: T1070.001 Indicator Removal: Clear Windows Event Logs

**False positives**

- Documented maintenance that resets logs (should be pre-announced)

### SIEM-1017 · Account Added to Privileged Group

A user was added to a highly privileged group.

**Logic**

- eventType ∈ {GROUP_MEMBERSHIP_ADD}
- group ∈ {Domain Admins, Enterprise Admins, Administrators, sudo, wheel}

**ATT&CK:** Persistence: T1098 Account Manipulation; Privilege Escalation: T1098 Account Manipulation

**False positives**

- Approved provisioning; correlate with a change ticket

### SIEM-1018 · Burst of Administrative Changes

Ten or more account or policy changes by one administrator within ten minutes.

**Logic**

- eventType ∈ {ADMIN_ACTION, USER_CREATED, ROLE_ASSIGNED, PASSWORD_RESET, POLICY_CHANGE}
- count ≥ 10 per userName within 600s
- repeat alerts for the same group suppressed for 1800s

**ATT&CK:** Persistence: T1136 Create Account; Persistence: T1098 Account Manipulation

**False positives**

- Onboarding scripts and bulk administration
- Identity sync jobs running under a named account
