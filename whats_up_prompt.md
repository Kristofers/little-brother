# Audit analysis prompt

This is a full audit of an Intune/MDM-managed macOS developer machine. Analyze the
attached audit files (`01_*` through `09_*`) and report factually on what the employer
can actually see and do. Ignore `whats_up_prompt.md` if it is attached — it is these
instructions, not data.

## Tone and form

- Strictly neutral and objective. Report the facts and their concrete consequences.
  Do not judge them and do not take the side of either the user's privacy or the
  employer's control. The reader draws the conclusions.
- Never describe an observation as good, bad, fortunate, unfortunate, best case or
  worst case. Avoid loaded and leading words like "worst case", "fortunately",
  "good news", "just", "only", "scary", "worrying", "nothing to worry about". State
  what is the case, not how one should feel about it.
- Present symmetrically: state both what is visible and what is not, without framing
  one as a relief or the other as a threat.
- Example of the desired phrasing: write "the destination domain of the tunneled
  traffic is visible, the page content is not", NOT "in the worst case the
  destination domain is visible, never the content".
- Distinguish what a component CAN do from what it actually DOES in this
  configuration, but describe both neutrally.
- Do not address the reader as "you". Write impersonally about the machine, the user
  and a developer.
- Explain technical things so a non-specialist understands, without losing precision.
- Do not obscure or hand-wave. If something cannot be determined from the files, or is
  uncertain, say so plainly rather than guessing or glossing over it.
- Illustrate every conclusion with concrete, everyday examples of what it means in
  practice, phrased impersonally. For example: "when a developer opens a private
  document on the machine ...", "when a user signs in to a private web service ...",
  "when a password is copied from a password manager ...". The examples should make
  it easy to compare against one's own behavior, without judging that behavior.

## Format

- Write the whole report in Markdown with clear structure: headings, lists and
  tables where they fit.
- Illustrate flows and relationships with Mermaid diagrams where it makes things
  clearer, e.g. how traffic is routed (straight out vs through the tunnel), which
  components see what, or where the boundary of visibility lies. Put each diagram in
  a fenced code block tagged `mermaid`. Do not use images or screenshots.

## Audience

The report should work for several roles at once — a developer who wants to
understand their day-to-day and privacy, a tech and IP lead, and a CISO and
infrastructure manager assessing the security posture. Structure it so everyone gets
something, and mark which part is most relevant to whom.

## Part 1 — Method

Open the report with this part before anything else.

- State what the report is based on: the attached audit files (`01_*` through
  `09_*`), a read-only local snapshot of the machine. The tool that produced them
  reads the machine and changes nothing.
- Note that the files are normally redacted before they are shared. The redaction
  masks personal and machine identifiers (names, usernames, host and computer names,
  serial number, hardware UUID, email addresses, tokens, MAC addresses, GUIDs) and
  any company or project terms passed to the tool. IP addresses are left unmasked on
  purpose, because masking them would remove the tunnel and routing evidence.
- Give a clear summary of whether the analysed material contains any data that, if
  leaked, could point a reader to a specific person or company. Go through the files
  by identifier category and, for each, say whether it appears in cleartext, appears
  masked, or is absent:
  - personal identifiers — names, usernames, email addresses
  - machine identifiers — serial number, hardware UUID, MAC addresses
  - organisation identifiers — company or project names, internal domains
  - network identifiers — IP addresses
- If any cleartext data that could identify a person or company remains, list it with
  the file it appears in so the reader can judge whether the material is safe to share
  further. If nothing identifying remains, say so plainly.

## Part 2 — What can the employer see and do today?

- Can files on the machine be read, and if so the content or just metadata?
- Are the visited sites visible? At the domain level or page content too?
- Is everything monitored, or only work-related activity? Does being signed in to the
  work account vs private use matter?
- Describe the consequences for a user in practice.

## Part 3 — Security posture under zero trust

Premise: employees are assumed honest, but an attacker (threat actor) who hijacks the
machine or the account is not. The protection should therefore target the attacker,
not the employee. The company should be able to detect a compromised machine or a
hijacked account (malware, stolen sessions, data or source code/IP leaking out), but
not monitor the employee's private behavior. Assess the actual configuration against
that principle:

- What is reasonable and should stay?
- What goes further than necessary and should be reconsidered?
- What is missing to actually catch a compromised machine or protect IP?

Clearly flag if a protective component is deployed but not active.

## Part 4 — Where do personal accounts and data belong?

Given the monitoring posture in Parts 2 and 3, explain why a work machine is
provisioned for work and why personal accounts and data fit naturally on a personal
device. The separation serves both sides: it keeps personal credentials off the
monitored surfaces, and it keeps the employer from holding those credentials on a
managed device. With a personal password manager (e.g. Bitwarden) and private notes
(e.g. Apple Notes) as concrete examples, note which of the monitored surfaces from
Parts 2 and 3 each would touch if kept on this machine. Where some personal use is
unavoidable, give the one or two choices that change what lands on those surfaces:
prefer a dedicated app over a browser extension, and keep personal storage out of any
work-synced location.

## Summary

End with a short, factual summary: what the machine actually monitors and does not
monitor, and what it protects against and does not. Restate, in one or two sentences
and mirroring the Method part, whether the analysed material contains any data that,
if leaked, could point a reader to a specific person or company. Then list the most
important actions split into what a user can do and what a security or infrastructure
owner should follow up on. Do not rank the monitoring on a scale and do not express an
opinion on whether the level is high or low.
