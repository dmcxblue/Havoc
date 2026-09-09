# Lessons

Read at the start of every session. Append only; correct with a dated note. Consolidate into Principles when the file passes 100 lines.

## Principles
<consolidated ALWAYS / NEVER rules, newest last>

## Entries

## YYYY-MM-DD — example entry, delete me
- Mistake: added a retry around a flaky call instead of finding why it failed
- Wanted: find the cause; the call failed because the client was created before config loaded
- Why: a retry hides an ordering bug and it will come back somewhere else
- Rule: NEVER add a retry, sleep, or try/except as a fix without naming the root cause in the commit message
