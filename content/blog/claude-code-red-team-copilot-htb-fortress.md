# Claude Code as a Red Team Copilot: Hacking HTB Fortress AWS

*April 2026*

I got to Pro Hacker on HackTheBox the old way. Hours of nmap scans, manually crafting SQLi payloads, reading the same OWASP page for the third time at 2am. That grind taught me more about offensive security than any course.

These days I have a buddy doing the heavy lifting. Claude Code sits in my terminal, writes exploit scripts, chains API calls, and automates the tedious parts while I focus on strategy and judgment calls. We ran it against an HTB Fortress challenge and pulled several flags in a single session.

This isn't a story about AI replacing pentesters. It's about what happens when you pair attack intuition with something that can write a threaded brute-forcer in 30 seconds.

## The Target

The Fortress challenge is built around a fictional company running a mix of Flask web apps, Apache Airflow, a custom AWS API endpoint backed by LocalStack, an exposed `.git` repo, and a Windows Domain Controller.

Multiple subdomains, multiple Docker containers, a simulated AWS environment, and a privilege escalation chain from basic web vulns all the way to IAM admin. The attack surface is wide.

## What We Found (High Level)

I'm keeping this deliberately vague to respect HTB's rules. No flags, no direct solutions. Just the categories of vulnerabilities we encountered and how Claude Code helped with each.

### Broken Access Control (IDOR)

One of the web apps had an API endpoint that accepted user identifiers. The identifiers weren't random enough. Claude Code wrote a threaded brute-forcer that found the admin account quickly. The key insight was recognizing the identifier format and realizing it was enumerable.

**Claude Code's role:** Wrote the concurrent testing script. I identified the vulnerable endpoint and the pattern.

### Server-Side Request Forgery

An admin-only healthcheck endpoint accepted URLs and fetched them server-side. Classic SSRF pattern. Used it to reach internal services that weren't exposed externally.

**Claude Code's role:** Automated the request chaining and response decoding. I identified the target internal services.

### Cryptographic Weakness Leading to Code Execution

This was the most technically interesting chain. A web application used JWT authentication with a specific signing algorithm. The implementation had a cryptographic flaw that allowed key recovery from observed signatures.

Once we had the key, we forged tokens and accessed restricted functionality. That functionality had a template injection vulnerability with a character blacklist. The bypass required passing payloads through an indirect channel.

**Claude Code's role:** Derived the cryptographic key recovery math, built the token forgery, and constructed the template injection payload chain. I identified the cryptographic weakness and the injection point.

### Binary Analysis

One of the compromised containers had a custom binary. Claude Code helped analyze it, identifying a non-standard authentication mechanism with hardcoded credentials.

**Claude Code's role:** Ran the binary through analysis tools and identified the authentication logic. I decided which binary to focus on and how to use the recovered credentials.

### SQL Injection with Filter Bypass

A search endpoint had SQL injection behind a character blacklist. The blacklist was case-sensitive. Mixed case keywords bypassed it entirely, giving access to the full database.

**Claude Code's role:** Built the extraction pipeline, enumerated schemas, and handled the case-sensitivity bypass. I identified the injection point and recognized the filter weakness.

### AWS Privilege Escalation Chain

Credentials extracted from the database gave access to the simulated AWS environment. From there, the attack chain involved SNS subscription manipulation, IAM enumeration, and Lambda-based privilege escalation paths.

**Claude Code's role:** Set up boto3 sessions, enumerated all available AWS services, and handled the API interactions. I mapped the privilege escalation path and identified which credentials to chain.

## What Claude Code Actually Did

It wasn't just autocomplete. It was running execution while I directed strategy:

- **Exploit scripting**: Wrote key recovery algorithms, token forgery, injection payloads, and brute-forcers from scratch
- **AWS API enumeration**: Handled SigV4 signing, tried every available API operation, mapped permissions
- **Database extraction**: Built extraction pipelines, enumerated schemas and tables
- **Network reconnaissance**: Port scanned from compromised containers, mapped Docker networks
- **Service interaction**: Managed subscriptions, handled async responses with retry logic

What it couldn't do: decide which attack path to pursue when multiple options existed, recognize when brute-forcing meant we were on the wrong track, or know when to step back and try something fundamentally different. That's still the human's job.

## Takeaway

Claude Code turned a multi-day fortress grind into a focused session. The things that used to eat hours (writing extraction scripts, handling JWT crypto, managing AWS API calls) now take seconds. The strategy, intuition, and knowing when to pivot are still entirely human.

It's pair programming for pentesting. I wouldn't send it solo against a target. But I wouldn't go back to grinding without it either.
