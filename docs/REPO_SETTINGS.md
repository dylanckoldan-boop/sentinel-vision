# Repository settings

Some protections can't be stored in the repository: they're settings on GitHub that only the owner can change.
This page lists them so they can be checked (audit finding SV-B03). Check them after any change to who has access,
and at each quarterly review.

## Branch protection for `main`

Settings → Rules → Rulesets (or Branches → Branch protection rules) → `main`:

- [ ] Require a pull request before merging
- [ ] Require review from Code Owners (uses [.github/CODEOWNERS](../.github/CODEOWNERS))
- [ ] Require status checks to pass: `CI / lint`, `CI / test` (Windows, macOS and Linux) and `Website / build`
- [ ] Block force pushes
- [ ] Restrict deletions
- [ ] Bypass list: only the owner, and only "for pull requests". GitHub never lets authors approve their own pull
      requests, so with a single maintainer the owner's own pull requests still need this; everyone else's need the
      owner's review. Nobody can push to `main` directly.

## Release environment

The publish job in `release.yml` runs in the `release` environment, so the signing key is only handed to it after
approval.

Settings → Environments → `release` (created the first time the job runs; create it by hand before the next release):

- [ ] Required reviewers: the owner
- [ ] Deployment branches and tags: `main` and tags matching `v*` only
- [ ] Move the `SV_SIGNING_KEY` secret from repository secrets into this environment's secrets, then delete the
      repository-level copy, so no other workflow can read it

## GitHub Pages

Settings → Pages → Build and deployment → Source: **GitHub Actions**. The `github-pages` environment should allow
deployments from `main` only.

## Actions

Settings → Actions → General:

- [ ] Workflow permissions: **Read repository contents** (each workflow asks for more only where it needs it)
- [ ] Allow GitHub Actions to create and approve pull requests: **off**
- [ ] Fork pull request workflows: require approval for first-time contributors

## Security

Settings → Code security:

- [ ] Private vulnerability reporting: **on** (SECURITY.md sends reports there)
- [ ] Dependabot alerts and security updates: **on**
- [ ] Secret scanning and push protection: **on**

## Accounts

- [ ] Two-factor authentication on the owner account, with a security key or passkey
- [ ] No other account has admin or write access, unless it's listed here with the reason
