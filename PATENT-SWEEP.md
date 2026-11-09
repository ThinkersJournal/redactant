# Patent sweep: redactant 0.1.1 @ b502904

Date: 2026-11-09; Run by: redactant lane, Sonnet 5.5; Method: AI-assisted web search (US-only `WebSearch`, patents.google.com),
then the independent claims of the closest hits read with `tools/patent-claims.py` (Google Patents pages); NOT legal advice; NOT a
freedom-to-operate opinion. There is no attorney. Process: `C:\Projects\PATENT-SWEEP-PROCESS.md`.

**Status: first pass COMPLETE for the routes run; no `needs-review`.** Routes NOT run: USPTO full-text, Espacenet, WIPO, assignee
searches, non-US grants. The PM accepted this scope as enough for the first publish under the portfolio rule (PM message to the lane, 2026-11-09; a reading, not legal advice); the limits below stand.

Scope: everything in the crate at 0.1.1: `Secret<T>`, `Scrubber`, `Fingerprint`/`FingerprintKey`, the `serde` feature, and the
canary test method in `tests/`.

## Ideas swept
1. A wrapper type whose `Display` and `Debug` print a fixed placeholder, whose value is reachable only through one explicit
   accessor, and which has no `Clone`, `Deref`, `AsRef` or `Into` that would release it.
2. The wrapper overwrites (zeroizes) its contents when it is dropped.
3. A short tag of a secret, computed as the first 4 bytes of HMAC-SHA-256 under a caller-held key, printed as `fp:` plus hex, so
   log lines can be correlated without revealing the secret.
4. A scrubber holding a set of registered secret strings that replaces every occurrence in a text, longest secret first, with
   the placeholder; it also renders an error and its whole `source()` chain before cleaning; and it refuses to register an empty,
   under-4-byte or non-UTF-8 secret.
5. Serialization of the wrapper writes the placeholder, and deserialization refuses a value equal to the placeholder (so a
   write-then-read round trip cannot silently turn the placeholder into the secret).
6. A test method: push a canary value through every formatting path, assert on bytes, and prove each assertion can fail with a
   negative control (a deliberately leaking mutation).
7. A "whole-message drop": if any registered secret appears in a message, the entire message is replaced by a fixed notice.

Ideas 1, 2, 3 and 7 are old and heavily published in practice (secret types in many languages, `memset`/zeroize on free, HMAC
fingerprints, log redaction); they were searched to cite the nearest claims, not because novelty is claimed.

## Queries (source: WebSearch limited to patents.google.com, US-only; date 2026-11-09)
| # | Idea | Query |
|---|---|---|
| Q1 | 1 | `patent wrapper object sensitive value masks string representation prevents logging, value accessible only through explicit accessor method` |
| Q2 | 2 | `patent overwrite secret data in memory with zeros when object destroyed or released to prevent sensitive data remaining in memory` |
| Q3 | 3 | `patent keyed hash truncated fingerprint of password or secret written to log to correlate occurrences without revealing the secret` |
| Q4 | 4, 7 | `patent redact known secret values from log messages and error messages by searching text for registered secret strings and replacing with placeholder` |
| Q5 | 5 | `patent serialization of sensitive data field replaced with placeholder when serialized to JSON, prevent secret in configuration dump or log` |
| Q6 | 6 | `patent testing method inserting canary string into sensitive field and verifying canary absent from all log outputs, mutation to verify test detects leak` |
| Q7 | 5 | `patent reject configuration value equal to redaction placeholder when loading, redacted value read back as credential, error detecting masked value` |
| Q8 | 1 | `patent sensitive data type class overrides toString to return masked text, value retrievable only by explicit method, programming language secret string type` (domains: patents.google.com, patft.uspto.gov, ppubs.uspto.gov) |

Positive control: every query returned patent pages (Google Patents / USPTO print pages), and Q4 surfaced US11341270B2, a real
log-redaction patent, so the search reaches the field. A null for one idea means no hit surfaced, not that none exists: Q6
(canary plus mutation control) and Q7 (placeholder refusal on read-back) surfaced nothing close.

## Hits
Claims read: every independent claim, from Google Patents text (machine-converted; check the official record before quoting).
For the active patents the limitation relied on appears early in each independent claim; I read that part and did not need the
dependent claims. Status is Google Patents' field, not the official record; "est." is Google's expiry estimate.

| # | patent | title | assignee | status | claims read | overlap | our difference | verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | US11341270B2 | Automatically redacting logs | IBM | Active; est. 2040-04-18 | 1, 9, 17 | a logging service searches log entries for registered secret-derived strings and redacts them | every independent claim needs registration of a secret **fingerprint** (claim 1: a first portion of a split secret, chosen when the second portion's entropy exceeds a threshold), a **protection time window** during which the logging service monitors, an optimized search list, and removal and re-optimisation of the list when a window expires. We have no split, no entropy test, no time window, no expiry, no logging service: the scrubber is a call on text the caller already has | clear (watch: do not add time-windowed protection with expiry-driven search-list regeneration, or entropy-split registration) |
| 2 | US10073980B1 | System for assuring security of sensitive data on a host | Amazon | Active; est. 2036-08-07 | 1, 6, 18 | values found in messages are searched for in log data and prevented from being included | every independent claim needs a **data classification tag** in a message and parsing the message to find the tagged value, adding it to watch data, then **searching log data** for it. We register secrets by hand from a `Secret`, read no messages, parse no tags and search no logs | clear (watch: do not add tag-driven discovery of secrets from messages plus a log-search monitor) |
| 3 | US9910994B1 | System for assuring security of sensitive data on a host (sibling) | Amazon | Active; est. 2036-08-07 | 1, 2, 5, 16 | same family | same: classification tag in an API message, watch data, counting occurrences in log data against a threshold (claim 1 also samples messages by a pseudorandom generator) | clear (same watch) |
| 4 | US9589146B2 | Hiding sensitive data in log files | IBM, now Airbnb | Expired (fee); est. 2034-06-02 | 1, 5, 9 | masks sensitive data before it reaches a log | needs an OS-embedded log interceptor daemon, an analytics engine with a confidence index, and a knowledge base of log-file names and customer data updated on masking. We intercept nothing and score nothing | clear |
| 5 | US9721094B2 | Determining privacy leaks | IBM | Expired (fee); est. 2035-07-16 | 1, 7, 13 | inserts a unique signature (canary) into private data and looks for it in outputs | claims are a mobile device application given private data, with the signature monitored in the public portions of the device file system. Ours is a unit test that formats a value in-process and checks the bytes; no device, no application sandbox, no file-system monitor, and no negative-control mutation step | clear (idea 6) |
| 6 | US8204929B2 | Hiding sensitive information | IBM, now Kyndryl | Active; est. 2029-04-06 | 1, 10, 19 | masks sensitive input | needs a masking factor combining a masking number generated at a second terminal, securely transmitted and then deleted. Nothing like it here | clear |
| 7 | US20170149793A1 | Anonymizing log entries | Symantec, now CA | Active (per Google; an application number, confirm the grant on the official record) | 1, 10, 19 | applies an anonymization policy to sensitive fields in logs | claims need detecting a data pattern across many log entries (message-template learning), finding variable fields and evaluating them as sensitive. We run no analysis of logs | clear |
| 8 | US11080164B2 | Time travel source code debugger incorporating redaction of sensitive information | Ozcode | Active; est. 2040-03-06 | 1, 14, 20 | replaces field values of sensitive variables | a production debugger simulating execution out of process with a memory delta buffer and checkpoints | clear |
| 9 | US8590034B2 | Stateful information redaction | individual | Expired (fee); est. 2026-08-10 | 1, 5 | substitutes sensitive information with fixed characters | a database-protocol redaction appliance intercepting requests and responses with per-session rules | clear |
| 10 | US20160379010A1 | Masking sensitive data in mobile applications | IBM | Active; est. 2035-07-19 | 1, 9, 15 | masks data by rule | masks at display time in a mobile app by instrumenting the application binary | clear |
| 11 | US20140164405A1 | Dynamic data masking | Institute for Information Industry | Abandoned | 1, 6 | marks sensitive keys and masks | a database writes sensitive keys and builds a filtering rule on write | clear (abandoned) |
| 12 | US20130167192A1 | Data pattern matching, masking and removal of sensitive data | Elevance Health | Abandoned | 1, 2, 3 | removes or masks sensitive data in a response | request-context policy enforcement over structured and unstructured repositories | clear (abandoned) |
| 13 | WO2015175649A1 | Handling value types | Oracle | Ceased | 1 | value types behind access methods | a VM storing value types in containers of different sizes via lower-level instructions; unrelated to secrecy | clear |
| 14 | US5249231A | Memory tagging for object reuse protection | Motorola, now General Dynamics | Expired (lifetime) | 1, 11, 16 | protects freed memory from reuse by another process | tag fields compared on read to deny a different subject; no zeroing on drop | clear (idea 2) |
| 15 | US10102383B2 | Permanently erasing mechanism for encryption information | QuintessenceLabs | Active | 1, 15 | zeroisation of key material | a hardware security device with a one-time-pad encryption subsystem and a bypass channel | clear (idea 2) |
| 16 | US8130554B1 | Securely erasing flash-based memory | EMC | Active; est. 2031-01-05 | 1, 15 | overwrites old data | flash logical-to-physical remapping and an "obscure operation" on the old physical location | clear (idea 2) |
| 17 | US10209907B2 | Secure removal of sensitive data | Microsoft | Active; est. 2036-07-23 | 1, 9, 17 | removal of spilled data | a cloud-storage workflow copying the data structure without remnants and redirecting connections | clear |

Idea 3 (a keyed truncated fingerprint for log correlation): the search surfaced only patents about fingerprinting biometrics,
DNS and generic keyed hashing (WO2020150880A1, EP3076584A1, US10903997B2, US20170272251A1) plus a non-patent paper (arXiv
2603.06540) that describes stable keyed hashes for device logs. I did not read those claims: their subject is unrelated, so they
are listed as **unread**, not `clear`. HMAC itself (RFC 2104, 1997) is not ours; we claim nothing in it.

Seen in results and NOT read (unread, no verdict): US10140296B2, US9892278B2, US8458487B1, US7778419B2, US8086615B2,
US8943332B2, US9338013B2, US20060085761A1, US20110113050A1, US20090048997A1, US20060074897A1, US20100205189A1, US12657337,
US12212578B2, US20240289490A1, US11042525B2, US4974167A, US9317218B1, US9983642B2, US6182223B1.

## Design constraints that come out of the sweep (so a later change does not walk into a claim)
- **Scrubber (hits 1, 2, 3):** keep registration manual and explicit (`register(&Secret)`). Do not add a protection time window
  with expiry, an entropy-split or prefix registration, a classification-tag parser that discovers secrets in messages, or a monitor
  that searches existing log data. Any of those needs a re-sweep first.
- **Canary tests (hit 5):** keep them in-process unit tests; no device file-system monitoring.

## Needs review (to the PM)
None.

## Limitations
- AI-assisted; eight general-web queries plus claim reads of 17 documents. A "clear" means no overlap on any independent claim
  that I read, with the reason given; it is not a clearance. Not legal advice.
- Routes NOT run: USPTO full-text and assignee searches, Espacenet, WIPO, non-US grants, and Google Patents' own query endpoint.
  The vendor angle (secret-management products, logging vendors: Splunk, Datadog, HashiCorp, 1Password, CyberArk) was not
  searched by assignee, so absence of their patents here proves nothing.
- Statuses and expiry dates are Google Patents' fields, not the official record; confirm anything that matters (US11341270B2,
  US10073980B1, US9910994B1 are Active and the closest).
- Software idioms (secret wrapper types, zeroize on drop, HMAC) are widely published as prior art in open-source libraries in many
  languages; that is not a patent search and is not relied on for any verdict.
- Re-sweep when a new family of capability is added (see the constraints above) and at least yearly after release.
