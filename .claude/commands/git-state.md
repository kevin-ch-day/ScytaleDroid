# git-state

Read-only: git branch --show-current; git worktree list; git status --short;
git branch -vv; git log --oneline @{upstream}..HEAD.
If no upstream exists, say UNAVAILABLE and show git log --oneline main..HEAD
as a local comparison, not remote state. Do not fetch, stage, stash, switch or commit.
