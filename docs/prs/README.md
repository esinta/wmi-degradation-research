# Archived pull requests #93, #115 and #118

This folder is an extract of three merged pull requests from the author's private
product repository (Esinta's `esinta-endpoints`). The section "What degrades is the client" in the
paper draws on their measurements. Readers cannot open the repository, so the pull requests'
descriptions and measurement comments are archived here.

| PR | Title | Merged (UTC) | Merge commit |
|---|---|---|---|
| #93 | fix(agent): WMI max-age recycling works again on a full pool | 2026-09-24T21:56:02Z | `8ada92690fb5dc1b851625e35781ae9d04e1e990` |
| #115 | fix(wmi): clear SAFEARRAY property values (native memory leak) | 2026-09-25T21:47:13Z | `41894f4dd217fda67e70102b225c9e11ddf02605` |
| #118 | fix(wmi): run each connection's COM calls on its own STA thread (~3x less WMI CPU) | 2026-09-28T19:07:26Z | `b1c18168d1f496fff85361ba6316729e366d77e0` |

## Files

- `pr-93.md`, `pr-115.md`, `pr-118.md`: each pull request's description and all of its
  comments, reproduced verbatim in posting order. None of them had review comments.
  The three comments on #93 were posted after it was merged.
- `REDACTIONS.md`: every change made to the verbatim text, with the reason.

## Notes for readers

- Commit hashes, build hashes, file paths and references to other pull requests (#69,
  #109, #111 and #112; #93 and #115 inside later ones) in the text refer to the private repository and cannot be resolved
  from outside it.
- "Laptop" and "VM" are the two lab hosts used for the measurements. The text itself
  does not name their operating systems.
- The code changes (diffs) are not reproduced here.
