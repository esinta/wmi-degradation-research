# Redactions

Every change made to the verbatim pull request text in `pr-93.md`, `pr-115.md` and `pr-118.md`.

| # | File | Location | Removed | Replaced with | Reason |
|---|---|---|---|---|---|
| 1 | `pr-115.md` | End of the PR description, after the "Generated with Claude Code" line | Link to a private Claude Code session (`https://claude.ai/code/session_…`) | `[url]` | Internal URL to a private session; not resolvable by readers |
| 2 | `pr-118.md` | End of the PR description, after the "Generated with Claude Code" line | The same private session link | `[url]` | Internal URL to a private session |
| 3-5 | `pr-115.md` | Source line above each of the 3 comments | Comment author's GitHub username and display name | `[name]` | Personal name / username |
| 6-7 | `pr-118.md` | Source line above each of the 2 comments | Comment author's GitHub username and display name | `[name]` | Personal name / username |
| 8-9 | `pr-115.md`, `pr-118.md` | Header | PR author's username and display name (GitHub metadata, not part of the PR text) | omitted | Personal name / username |
| 10 | `pr-93.md` | End of the PR description, after the "Generated with Claude Code" line | Link to a different private Claude Code session (`https://claude.ai/code/session_…`) | `[url]` | Internal URL to a private session |
| 11-13 | `pr-93.md` | Source line above each of the 3 comments | Comment author's GitHub username and display name | `[name]` | Personal name / username |
| 14 | `pr-93.md` | Header | PR author's username and display name | omitted | Personal name / username |

Rows 3-9 and 11-14 are in metadata that the extract adds around the verbatim text; the text
itself never names a person.

## Counts by type

| Type | Count |
|---|---|
| Internal URLs | 3 (all in the verbatim text) |
| Personal names / usernames | 11 (author metadata only: 8 comment source lines + 3 headers) |
| Credentials / tokens | 0 found |
| IP addresses | 0 found |
| Hostnames (non-generic) | 0 found; the text says only "laptop", "VM", "lab VM" |
| Emails | 0 found |
| Local paths with user names | 0 found |
| Customer or site names | 0 found |

## Checked and left in (approved by the author, 2026-10-25)

- The public link `https://claude.com/claude-code` in the "Generated with Claude Code" footer of both descriptions.
- Repository-relative paths (`internal/agent/wmi/*.go`, `test/leakprobe`, `test/lab/fault_test.ps1`, `docs/development/handoffs/2026-09-26-agent-native-memory-leak.md`). They contain no user names, but they show the private repository's layout and name an internal handoff document.
- Private-repository commit and build identifiers (`b9c8636`, `f8c7d789`, `b181563b`, `fe74044`, `d53e9bc`, `md5 6c7956ae`) and references to other private pull requests (#112; #115 inside #118).
- From `pr-93.md`: the lab-host sampler path `C:\ProgramData\EsintaSoak\soak.csv` (a local path, but with no user name; it names the product), the agent instance IDs `8c0d83f0` (laptop) and `1ca05fe3` (VM), build identifiers `f8c7d789`, `main@8ada926`, `b04fd72`, `main@b9c8636`, the CSV name pattern `soak_pre_main_*.csv`, and references to #69, #109, #111 and #112. The phrase "At the user's request" names no one.
- Firewall rule counts of the two lab hosts (696 and 468) and the process counts (~260 rows).
- The product name "Esinta" does not appear in the #115 or #118 text; in #93 it appears only inside the path `C:\ProgramData\EsintaSoak\soak.csv`.
