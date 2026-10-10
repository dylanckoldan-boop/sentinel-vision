## What and why

<!-- What does this change, and what problem does it solve? Link the issue: "Fixes #123" -->

## Checklist

- [ ] Tests added or updated, and `pytest` passes
- [ ] `ruff check src tests tools` and `ruff format --check src tests tools` pass
- [ ] No live malware samples are included (use the EICAR string assembled at runtime, or synthetic files)
- [ ] New parsing of untrusted input enforces size/depth limits and never executes content
- [ ] User-visible changes are described in `CHANGELOG.md` under an *Unreleased* heading
