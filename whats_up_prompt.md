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

## Part 1 — What can the employer see and do today?

- Can files on the machine be read, and if so the content or just metadata?
- Are the visited sites visible? At the domain level or page content too?
- Is everything monitored, or only work-related activity? Does being signed in to the
  work account vs private use matter?
- Describe the consequences for a user in practice.

## Part 2 — Security posture under zero trust

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

## Part 3 — How can a user keep personal data private?

This part is about a person's own **private** data on a work machine — a personal
password manager, personal notes — not about hiding work activity or evading security
controls. Work data and work activity remain subject to the employer's monitoring; the
goal here is only to keep genuinely personal data off the monitored surfaces in the first
place. Given the monitoring posture above, give practical advice for that: with a password
manager (e.g. Bitwarden) and private notes (e.g. Apple Notes) as examples, cover app vs
browser extension, master password and lock timers, clipboard, local storage vs iCloud,
and the simplest option of keeping personal accounts on a personal device instead.

## Summary

End with a short, factual summary: what the machine actually monitors and does not
monitor, and what it protects against and does not. Then list the most important
actions split into what a user can do and what a security or infrastructure owner
should follow up on. Do not rank the monitoring on a scale and do not express an
opinion on whether the level is high or low.
