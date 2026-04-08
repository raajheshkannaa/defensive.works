# Using Claude Code as a Red Team Copilot

*April 2026*

I got to Pro Hacker on HackTheBox the old way. Hours of nmap scans, hand-crafted SQLi payloads, reading the same OWASP page for the third time at 2am. That grind taught me more about offensive security than any course I've taken.

Now I have a copilot. Claude Code sits in my terminal while I work through pentesting engagements, CTF challenges, and lab environments. It writes the exploit scripts. I pick the targets.

This isn't a story about AI replacing pentesters. The judgment calls, the pivots, the "that brute-force isn't working, try something else" moments are still mine. But the hours I used to spend writing extraction scripts, wrestling with JWT crypto libraries, and debugging boto3 sessions? Those compress to seconds.

## What the Workflow Actually Looks Like

I'll walk through five categories of offensive work where Claude Code changes the speed of execution. These come from real engagements across multiple lab environments; I'm keeping targets and specifics vague on purpose.

### Broken Access Control

You find an API endpoint that takes a user identifier. The identifier is sequential, or low-entropy, or just a small integer someone thought nobody would guess. You need to test a range.

Before Claude Code, I'd write the brute-forcer myself. `requests`, a loop, some basic threading if I was feeling ambitious. 15 minutes minimum for something that works cleanly.

With Claude Code: "Write a threaded brute-forcer for this endpoint. Test IDs 1 through 1000. Highlight any response that doesn't contain 'Invalid.'" Working script in 20 seconds. I review the output, adjust the range, and run it. The actual finding takes maybe a minute from identification to confirmation.

The skill that still matters: recognizing that the identifier is enumerable in the first place. Claude Code can brute-force anything you point it at; knowing *what* to point it at is the human part.

### Cryptographic Attacks

JWT implementations with reused nonces. Weak signing algorithms. Fixed initialization vectors. These are math problems with known solutions, but the solutions are tedious to code by hand.

I've had Claude Code recover ECDSA private keys from signature pairs, forge JWTs with recovered keys, and chain the forged tokens into authenticated sessions. The math isn't new. It's textbook. But coding it from memory at midnight is where mistakes happen, and one wrong modular inverse means you're debugging crypto instead of hacking.

Claude Code writes the key recovery, I verify the math, and we move on to what the forged token gives us access to. That's the split: it handles the arithmetic, I handle the exploitation strategy.

### SQL Injection Extraction

You find the injection point. You confirm it returns data. Now you need to extract every table, column, and interesting row from a database you can't see directly.

The old workflow: write UNION queries by hand, adjust column counts, deal with character blacklists, slowly enumerate schema information one query at a time. An hour of mechanical work.

Claude Code builds the full extraction pipeline. It handles the column count alignment. It works around blacklists (case sensitivity, encoding tricks, alternate keywords). It writes the schema enumeration, pivots to interesting tables, and pulls the data. I tell it what to extract and review what comes back.

One engagement had a case-sensitive keyword blacklist. `UNION` was blocked; `UnIoN` walked right past it. Claude Code suggested the bypass in the same breath as writing the extraction query. That's not genius. It's pattern matching at speed. But it saved me 20 minutes of manual testing.

### AWS Post-Exploitation

AWS has hundreds of API calls across dozens of services. Post-compromise enumeration means systematically calling `List*` and `Describe*` across IAM, S3, ECS, Lambda, RDS, SecretsManager, and more. Then interpreting the results to find the privilege escalation path.

Claude Code handles the boto3 sessions, the SigV4 signing edge cases, and the systematic API crawl. It tries every service, reports what's accessible, and flags interesting findings (overprivileged roles, secrets with broad access, ECS clusters with `ExecuteCommand` enabled).

I map the kill chain. "This IAM user can `PassRole` to a Lambda execution role that has `AttachUserPolicy`. Classic Lambda privesc." Claude Code then writes the exploitation script. But identifying that path in a forest of IAM policies takes human pattern recognition that I haven't seen any model replicate reliably.

### Chaining Vulnerabilities

Individual bugs are interesting. Chains are where the real damage happens. Web vuln gives you credentials. Credentials give you cloud access. Cloud access gives you container access. Container access gives you data.

Claude Code is good at executing each link in the chain once I define the path. It can't see the chain. When I'm staring at a compromised container with network access to an internal database, five stolen AWS credentials of varying privilege levels, and a template injection that only works with a specific character blacklist bypass, the question isn't "can you code an exploit" but "which of these ten paths actually leads somewhere."

That's judgment. It comes from years of doing this manually, understanding which patterns lead to dead ends, and knowing when to abandon a path and try something else. Claude Code gets frustrated never. I get frustrated constantly. The combination works.

## What It Can't Do

I want to be honest about this because the "AI will replace pentesters" take is lazy.

**It can't prioritize.** Given five potential attack paths, it'll happily brute-force all five in parallel. Three of them are dead ends. A human with experience skips those and tries the one that smells right first.

**It can't read the room.** Sometimes a brute-force approach means you're barking up the wrong tree entirely. The vulnerability is somewhere else, and you need to step back and re-examine your assumptions. Claude Code will keep hammering the door you pointed it at until you tell it to stop.

**It can't improvise under novel conditions.** Known vulnerability classes with documented exploitation techniques? Excellent. Something weird you've never seen before that requires creative thinking? It'll try pattern-matching against similar things it's seen, which sometimes works and sometimes wastes time.

**It writes code that looks correct but might be subtly wrong.** Especially crypto. I always verify the math independently before trusting forged tokens or recovered keys. One wrong assumption about byte ordering can mean the difference between a valid exploit and garbage output.

## The Setup

For anyone who wants to try this workflow:

```bash
# Claude Code in the terminal, pentesting tools in scope
claude "You're assisting with an authorized penetration test. 
       I'll describe targets and goals. You write exploit scripts, 
       handle API interactions, and automate enumeration. 
       Always confirm before running anything destructive."
```

Give it context about your target. Share error messages, responses, and discovered endpoints. Let it see what you see. The more context it has about the environment, the better its suggestions get.

I keep a scratch file open with notes about what we've found, what we've tried, and what's left. Claude Code reads it and stays oriented. Without that shared state, you end up re-explaining the engagement every few prompts.

## So What

Claude Code turned multi-day CTF grinds into focused sessions. The mechanical work (writing scripts, managing sessions, extracting data) compresses by 10x. The thinking work (target selection, path analysis, creative pivots) stays entirely human.

It's pair programming for pentesting. I wouldn't send it solo against a target. But I'm not going back to grinding without it.
