# Patent sweep: redactant 0.1.1 @ b502904

Date: 2026-11-09; Run by: redactant lane, Sonnet 5.5; Method: AI-assisted web search (US-only `WebSearch`, patents.google.com),
then the independent claims of the closest hits read with `tools/patent-claims.py` (Google Patents pages); NOT legal advice; NOT a
freedom-to-operate opinion. There is no attorney. Process: `C:\Projects\PATENT-SWEEP-PROCESS.md`.

**Status: first pass COMPLETE for the routes run; no `needs-review`. A second pass on the (unbuilt) detector family is appended at the end (2026-11-14): one decision on the entropy class, answered: not built.** Routes NOT run: USPTO full-text, Espacenet, WIPO, assignee
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


---

# Re-sweep 2: the detector family (design only) @ 6f3a653

Date: 2026-11-14; Run by: redactant lane, Sonnet 5.5; scope of this pass: the **detector** described in `docs/DETECT.md` (PR #20),
which is **not built**. Same method and same limits as the first pass: AI-assisted search, independent claims read whole with the
shared claims tool (Google Patents text, machine-converted), **NOT legal advice, NOT a freedom-to-operate opinion, no attorney**.
Scope approved by the PM 2026-11-14 (wider routes). **Verdict wording (PM 2026-11-14): "outside as read", with the limitation
quoted; never "clear".** Gate: no detector code until the PM has read this.

## Ideas swept (detector family)
8. Screening text for secret-shaped strings by anchored patterns (PEM header, URL credentials, JWT structure, vendor token
   prefixes) and refusing the write on a match.
9. Classifying a candidate token as a credential by a **fixed** Shannon-entropy threshold (opt-in class `HighEntropy`).
10. Classifying by key name plus assignment plus value shape (`password=...`; opt-in class `KeyValueSecret`).
11. A result that carries only a class (and optionally a byte range), never the matched text, so it can be logged.

## Routes actually run, and not run
Run: Google Patents through the web-search tool, six queries (below); full independent claims of eleven documents read with the
claims tool. **Not run, and why:** USPTO full-text search and Espacenet are interactive applications my tools cannot query (the
search surfaced `image-ppubs.uspto.gov` PDF links only; those were not read); WIPO and non-US grants not searched; **assignee
searches** were attempted by name (GitGuardian, GitHub, Trufflesec) in one query and found no patent under those names in the
results, which proves nothing about their portfolios. So the PM's wider scope was tried, and the part my tools could not do is
stated, not skipped silently.

## Queries (source: WebSearch limited to patents.google.com unless stated; 2026-11-14)
| # | Idea | Query |
|---|---|---|
| Q9 | 8, 9 | `patent detecting secrets credentials in text using regular expression patterns and entropy of candidate string, source code repository secret scanning` |
| Q10 | 9 | `patent determine string is credential by Shannon entropy threshold and prefix pattern, API key token detection in documents` |
| Q11 | 8, 11 | `patent scanning data for private key PEM header, password assignment key-value, URL embedded credentials before storing, block storage of sensitive information, report category without revealing the value` |
| Q12 | 8 (vendors) | `GitGuardian OR GitHub OR Trufflesec patent secret detection credentials leakage method assignee` (domains: patents.google.com, patents.justia.com) |
| Q13 | 11 | `patent sensitive data detection result reports type of sensitive data found and location without including the sensitive value itself, data loss prevention match report masked` |
| Q14 | 10 | `patent identify password or API key in text by variable name keyword such as password secret token followed by assignment and value pattern, classify as secret` |

Positive control: Q9 and Q10 returned real secret-detection patents (US9619670B1 and others), so the search reaches the field. A
null for one idea means no hit surfaced: Q11 found nothing for **URL-embedded credentials** and nothing for a **class-only
result**; that is an absence of hits, not of patents.

## Hits (independent claims read whole; status and dates are Google Patents' fields, not the official record)
| # | patent | title | assignee | status | claims read | overlap | what the independent claim requires that we do not do | verdict |
|---|---|---|---|---|---|---|---|---|
| 18 | US9619670B1 | Detecting user credentials from inputted data | GitHub, now Microsoft | Active; est. 2035-02-25 | 1, 18, 19 | decides whether data is a credential by a run of ASCII bytes of at least a threshold length and a credential test (claims 2, 7-9 add entropy, pattern and prefix) | claim 1: "storing, in a data chunk storage, the data chunk"; "analyzing each byte from a last N data chunks"; "determining, from the last N data chunks, a credential address range corresponding to the continuous number of bytes". We scan one `&str` with no chunk storage, no last-N-chunk run tracking and no address range | **outside as read** (watch: a streaming scanner that carries a byte run across the last N chunks is this claim) |
| 19 | US9336381B1 | Entropy-based detection of sensitive information in code | Amazon | Active; est. 2034-03-23 | 1, 5, 13 | flags a part of a document whose entropy is at least a threshold as a security risk | claim 1: "analyzing an information entropy of a first document", "determining ... a baseline information entropy for the first document", "from the baseline ... determining a threshold information entropy", and "generating a second document ... disabled, removed, or replaced". Our entropy class would use a **fixed** threshold, with no document baseline and no second document | **outside as read for a fixed threshold**; **would read on a threshold derived from the input's own baseline entropy** (watch) |
| 20 | US20230063214A1 | Secret detection on computing platform | Google | Active per Google; **a published application, confirm the grant** | 1, 15, 20 | detects secrets in a data stream by comparing it with a repository of known secrets, which is what `Scrubber::appears_in` does (the v1 route, **already shipped**) | claim 1: each secret "is associated with one or more entities", and "in response to the detection, send an indication of the presence of the detected secrets to the one or more entities associated with the detected secrets". We keep no entity per secret and notify no one | **outside as read** (watch: do not add per-secret owners with notification on a hit; this touches SageAnt's put path too) |
| 21 | US11288376B2 | Identifying hard-coded secret vulnerability inside application source code | IBM | Active; est. 2040-04-23 | 1 | a rule set over a string's value and characteristics (length, name) to indicate a hard-coded secret | claim 1: "applying a lexical analysis to the source code", a first rule keyed on "a specified function with which it is associated" (an API call) **and** a second rule on value or characteristic, then "a likelihood and location in the source code" | **outside as read** (watch: no source-code lexing, no rule that treats a string passed to a named API as a secret) |
| 22 | US12299131B2 | Method, device, and computer readable medium for detecting vulnerability in source code | Samsung | Active; est. 2041-09-01 | 1 | keyword detection and credential patterns "requir[ing] an entropy verification" over value-assignment lines | claim 1: source code identified "based on a file extension or a file signature", "a different type of parser" per file type, "keywords ... obtained, by a keyword extractor based on a pre-configured formula", and a line-similarity condition "to reduce a false positivity" | **outside as read** (watch: no per-file-type parsing of assignments; no similarity-based false-positive filter) |
| 23 | US11550569B2 | Discovering and remediating hidden secrets in code files | CyberArk | Active | 1, 11 | detects hidden secrets in source files | claim 1: a control flow representation of the code, verification that the secret is "a live variable", a probability, ML-system feedback | outside as read |
| 24 | US11868768B2 | Detecting secrets in source code | JPMorgan Chase | Active; est. 2042-04-07 | 1, 10 | identifies secrets in source code | claim 1: trained ML model on labelled features, a GUI test file, and obsolete/usable/deprecated and production/development characteristics | outside as read (watch: no ML classifier) |
| 25 | US12500756B2 | Automated secret secure repositioning | DigiCert | Active; est. 2043-12-08 | 1, 13, 20 | scans for secrets by regex and file extension | claim 1: a policy engine mapping secret type to a FIPS PUB 140-2 level and automatically repositioning the secret and reconfiguring dependent services | outside as read |
| 26 | US12705381B2 | Smart result filtration for secret scanning | Microsoft | Active; est. 2044-05-20 | 1, 8, 15 | secret scanning results | claim 1: ML relevance scores from metadata features other than the text or patterns, removal below a threshold | outside as read |
| 27 | US8156159B2 | Data masking and unmasking of sensitive data | Verizon | Active; est. 2030-10-07 | 1 | records the type of sensitive elements | claim 1: a dynamic table per sensitive type loaded and masked in parallel into an output file or table. A search snippet (not read) says its sibling application US20100205189A1 records type with start and end positions, which is what our `Finding` would carry; claim 1 itself is about masking tables | outside as read |
| 28 | US10762192B2 | Cleartext password detection using machine learning | PayPal | Active; est. 2039-02-27 | 1 | flags textual data as a password anomaly | claim 1: a predictive text classifier predicting following characters from a corpus-trained model | outside as read (watch: no language-model classifier) |

Seen in results and **not read** (unread, no verdict): US10671750B2, US20170091680A1, US9268947B1, US11263335, US12073000B2, US12321496,
US20120272329A1, US9104878B1, US8799671B2, US20080184367A1, CN117708876B, US20170272251A1 (earlier), and the `image-ppubs.uspto.gov`
PDFs for 12705381, 12500756, 9619670, 9336381, 11868768, 11550569, 11288376 and 12299131 (read through Google Patents instead).
**Q11 specifically found nothing on URL-embedded credentials or a class-only result type**: treat idea 11 as unsearched to a
useful depth, not as free.

## Design constraints that come out of this pass (so a later change does not walk into a claim)
- **Entropy (hits 19, 18, 22; the IBM US11341270B2 watch item stands):** if `HighEntropy` is built, its threshold is a **fixed
  constant**, never derived from the scanned text's own entropy (hit 19), and the detector never writes a rewritten copy of the
  document (hit 19's "second document"). **Decided below: it is not built.**
- **Streaming (hit 18):** the detector scans one complete `&str` per call. No state is carried between calls, no "last N chunks",
  no byte-run bitmaps, no address ranges. A caller that chunks its input (SageAnt says its chunks are UTF-8 NFC) screens each
  chunk on its own; carrying a run across chunk boundaries inside redactant would be hit 18's claim.
- **Registered secrets (hit 20):** `Scrubber` keeps secrets without owners. Do not add an entity per secret or a notification to
  that entity on a match.
- **Key-name and source code (hits 21, 22):** no lexing or per-file-type parsing of source, no rule keyed on the API a string is
  passed to, no keyword-extraction formula, no similarity-based false-positive reduction.
- **No ML or language-model classifier (hits 24, 26, 28).**
- **Results (hit 27):** a `Finding` is a class and at most a range; it never holds the text.
- These add to the first pass's constraints (no time window, no entropy-split registration, no tag parser, no log monitor).

## Needs review (to the PM, then CireSnave): DECIDED 2026-11-14
**PM decision (patent-cautious, listed for CireSnave): `HighEntropy` is NOT built.** Nobody asked and four entropy-related patents are
Active (US9619670B1 to 2035, US9336381B1 to 2034, US12299131B2, US11341270B2). **Standing non-goal (PM): no owner notification in the
`Scrubber` or any put path (US20230063214A1).** The PM and CireSnave cannot run USPTO full text or Espacenet either, so the limit
stated under "Routes actually run, and not run" stands and the work moves on. The reasoning that led to the decision follows.

The **entropy** idea is the thin one. Two Active patents (hits 18 and 19,
Microsoft to 2035 and Amazon to 2034) claim entropy-based credential detection, a third (hit 22) requires "entropy verification",
and the first pass's IBM US11341270B2 claim turns on an entropy threshold. A fixed-threshold class sits outside each as read,
but the margin is the difference between a fixed and a derived threshold and between one `&str` and stored chunks, which a
reader with a lawyer's eye should see. **Decision asked: do not build `HighEntropy`, or build it only after CireSnave has read hits 18, 19 and 22. Answered: do not build it.** The default classes (PEM header, URL
credentials, JWT structure, provider prefixes) rest on anchored patterns and are outside every independent claim read here as I read them; that is a
reading of 11 documents, not a clearance.

## Limitations of this pass
- Six queries, eleven documents read; the routes in "Routes actually run, and not run" were not available to me. Absence of
  hits for URL credentials and for a class-only result is absence of hits.
- Statuses and expiry dates are Google Patents' fields; US20230063214A1 is an application and may not be granted.
- Software idioms (regex scanning, entropy as a heuristic) are widely published in open-source tools; that is not a patent search
  and is not relied on for any verdict.
- Re-sweep again before any detector code merges if the design changes, and at the latest by 2027-11-09 with the rest.
