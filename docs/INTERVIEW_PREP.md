# Sentinel: Interview prep

One page to practise from. These are model answers, not a script: say them in your own words, and change anything that is not true for you. An interviewer can tell a memorised answer from an understood one.

## The 60-second pitch

"SOC analysts spend their day turning logs into decisions, and I wanted to practise that whole loop, not just read about it. So I built Sentinel. It simulates five attacks as log lines, detects them with ten Sigma-style rules mapped to MITRE ATT&CK, and groups the alerts into one incident with a timeline and a PDF report. An AI model drafts the triage for each alert, and the analyst accepts or edits it.

The part I am proudest of is that every piece is explainable. Each rule is tested against the attack and against harmless look-alikes, each has a plain-English page saying why it fires, and one of the simulated phishing emails carries a real prompt-injection attempt that the app is built to resist. I built it with an AI coding tool, and I can walk you through any part of it."

Practise until you can say it without notes in about a minute.

## The architecture in one breath

"The simulator writes logs, the rule engine turns matches into alerts, correlation groups related alerts into incidents, the AI adds explanations beside them, and the report sums up the incident. It is one Python backend, one React front end, and one Docker container."

## Eight likely questions

**1. Why did you simulate logs instead of using a real lab?**
Three reasons. It is safe: nothing is attacked, so anyone can run it. It is repeatable: the same click gives the same attack, which is what lets me test that each rule fires on it and stays quiet on normal activity. And it kept my time on the analyst's side of the work, detection and triage, and not on maintaining virtual machines. The trade-off is that simulated logs are cleaner than real ones. Real logs have missing fields, clock drift and far more noise, and I would expect to tune every rule again against real data.

**2. How do your rules avoid false positives?**
Three ways. They test named fields, not raw text, so a value in one field cannot be mistaken for another. Most have a filter for the known harmless case: the upload rule ignores internal addresses, for example. And every rule has tests both ways: logs that must fire it and look-alike logs that must not, plus one test that runs 300 random half hours of normal activity through all ten rules and expects silence. I would not claim zero false positives. Each rule lists the harmless causes I know of, so the analyst knows what to rule out first.

**3. Why is the AI not making the final call?**
Because it can be confidently wrong, and it can be manipulated through the data it reads. When a decision turns out wrong, a named person has to be accountable for it. So in Sentinel the AI only suggests. Its triage is stored beside the alert and never changes the alert's severity or status. The card is marked "AI suggestion" until a person accepts or edits it, and the app works fully without AI.

**4. What is prompt injection, and how does Sentinel defend against it?**
It is hiding instructions inside data an AI will read. Logs are full of text the attacker chose: an email subject, a file name, a command line. Blocking suspicious phrases does not work, because the attacker just rewords. So the defence is structural. The instructions and the logs are sent separately. The logs sit in a marked evidence block that they cannot close, because angle brackets are escaped. The AI is told that block is evidence, never instructions. Its answer must fit a fixed format and it has no tools. And nothing changes until an analyst accepts. One simulated phishing email carries a real injection attempt as a test.

**5. How does this map to Security+?**
Directly, and every rule's Explain page names its topic. Brute force maps to password attacks and account lockout. Phishing maps to social engineering. The PowerShell rules map to indicators of malicious code. Privilege escalation maps to least privilege and account management. Exfiltration maps to data loss prevention. The incident report follows the incident response steps: detection, analysis, containment, eradication and recovery. And severity is judged against confidentiality, integrity and availability.

**6. What would you change for a real company?**
First, accounts and roles, with a record of who changed which status and why. Second, real log ingestion, with detection over a sliding time window: today the rules check each batch on its own. Third, the things in my threat model's accepted-risks list: rate limits, a proper database with backups, and the API key in a secrets manager with a spending cap. And I would tune every rule against that company's own normal activity, because what is normal differs everywhere.

**7. What was the hardest part?**
Getting rules to stay quiet. Making a rule fire on the attack is the easy half. The work was the near-misses: a colleague emailing a macro spreadsheet, IT running an encoded PowerShell script, a big upload to an internal server. Each of those had to not raise an alert, without loosening the rule so far that the real attack slipped through. That is where I understood why detection is called a trade-off.

*(If a different part was harder for you, say that one. A true answer beats a polished one.)*

**8. An AI wrote the code. What was your part?**
I am open about that: it says so in the README. I set the scope, the eight features and the five attacks, and made the decisions along the way, which are logged in the repo. I tested every phase myself before the next one started, and I did not move on until I could answer that phase's questions out loud. What I took from it is the understanding: I can read each rule, explain why it fires, explain the correlation logic and the prompt-injection defence, and say what I would change. Working with an AI assistant is also how a lot of security work is starting to be done, and knowing where it must not decide alone is part of what the project is about.

## Five terms to use naturally

| Term | What it means | In a sentence |
| --- | --- | --- |
| True positive | An alert that really was an attack | "I closed it as a true positive once I had confirmed the account was created by the attacker." |
| False positive | An alert on harmless activity | "A cloud backup would be a false positive for the large-upload rule, so the rule lists it as something to rule out." |
| ATT&CK technique | The method an attacker used, with an ID | "The encoded command maps to ATT&CK technique T1059.001, PowerShell." |
| Correlation | Linking separate alerts that belong to one attack | "Correlation is what turned nine alerts into one incident." |
| Containment | Stopping an attack spreading, before cleaning up | "Containment came first: isolate the workstation, then block the address." |

## Numbers worth remembering

- **5** attack scenarios and a full attack chain. **10** detection rules, two per attack.
- The full attack chain raises **9** alerts, grouped into **1** incident.
- Alerts are linked when they share a host or a user within **30** minutes.
- **223** automated tests. Every rule is tested both ways.
- **6** build phases, each ending with something working.

## Practise

1. Say the pitch out loud, timed, three times.
2. Open the app, run the full attack chain, and explain each screen to someone who does not work in IT.
3. Pick any rule in **Detections** and explain it without reading its page.
4. Ask a friend to pick three of the eight questions at random.
