# Repository settings

Some protections can't be stored in the repository: they're settings on GitHub that only the owner can change.
This page lists them so they can be checked (audit finding SV-B03). Check them after any change to who has access,
and at each quarterly review.

Ticked items were read back from GitHub on 31 October 2026. Items marked "check by hand" couldn't be read with the
access used for that check, so they stay unticked until the owner confirms them.

## Branch protection for `main`

Settings → Rules → Rulesets → "Protect main":

- [x] Require a pull request before merging (nobody can push to `main` directly)
- [x] Block force pushes
- [x] Restrict deletions
- [x] Bypass list: empty, so the rules apply to everyone, the owner included
- [ ] Require status checks to pass: add **`lint`** and the nine test jobs **`test (ubuntu-latest, 3.10)`**,
      `test (ubuntu-latest, 3.12)`, `test (ubuntu-latest, 3.13)`, `test (windows-latest, 3.10)`,
      `test (windows-latest, 3.12)`, `test (windows-latest, 3.13)`, `test (macos-latest, 3.10)`,
      `test (macos-latest, 3.12)` and `test (macos-latest, 3.13)`, source GitHub Actions. The rule exists but its list
      of checks is empty, so nothing is enforced yet. Don't add `build` (Website): it doesn't run on every pull
      request, and a required check that never runs blocks the merge.
- [ ] Require branches to be up to date before merging (the same rule's "strict" option)
- [ ] Code-owner review: leave **off** while you are the only maintainer and the maintaining Claude instances open
      pull requests under your account. GitHub never lets an author approve their own pull request, so it would block
      every merge. Review each pull request yourself before you press Merge instead; turn it on (with
      [.github/CODEOWNERS](../.github/CODEOWNERS)) when a second maintainer joins.

## Release environment

The publish job in `release.yml` runs in the `release` environment, so the signing key is only handed to it after
approval.

Settings → Environments → `release` (check by hand):

- [ ] Required reviewers: the owner
- [ ] Deployment branches and tags: tags matching `v*` only
- [ ] Move the `SV_SIGNING_KEY` secret from repository secrets into this environment's secrets, then delete the
      repository-level copy, so no other workflow can read it

## GitHub Pages

Settings → Pages → Build and deployment → Source: **GitHub Actions** (check by hand).

- [ ] Settings → Environments → `github-pages` → Deployment branches: `main` only

## Actions

Settings → Actions → General (check by hand):

- [ ] Workflow permissions: **Read repository contents** (each workflow asks for more only where it needs it)
- [ ] Allow GitHub Actions to create and approve pull requests: **off**
- [ ] Fork pull request workflows: require approval for first-time contributors

## Security

Settings → Code security:

- [x] Private vulnerability reporting: **on** (SECURITY.md sends reports there)
- [ ] Dependabot security updates: **on**. They were **off** on 31 October 2026; turn on Dependabot alerts first if
      they are off too.
- [x] Secret scanning and push protection: **on**

## Accounts

- [ ] Two-factor authentication on the owner account, with a security key or passkey (check by hand)
- [ ] No other account has admin or write access, unless it's listed here with the reason (check by hand)

## Verifying it worked

- [ ] A test pull request that fails `lint` or a test job can't be merged.
- [ ] A test report sent through **Report a vulnerability** reaches the owner.
- [ ] `git push` straight to `main` is rejected.
