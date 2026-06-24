# Release checklist

biscuit-haskell is part of the [Eclipse Biscuit](https://projects.eclipse.org/projects/technology.biscuit) project and as such needs to conform the eclipse project management guidelines.

Eclipse projects can only be released within the validity period of a release review (they last for 1 year).

## Pre-release

- make sure `README.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` are present and up-to-date
- make sure `LICENSE` is present and that all source files are properly annotated with copyright and license information
- make sure dependency license information is correctly vetted:

```bash
 cat cabal.project.freeze | rg == | sd 'constraints: ' ' ' | sd ',$' '' | sd '^ +' 'haskell/hackage/-/' | sd ' ==' '/' | sd '/any\.' '/' | java -jar org.eclipse.dash.licenses-1.1.0.jar - 
```
(you’ll need to download the [eclipse dash licenses jar](repo.eclipse.org/content/repositories/dash-licenses/org/eclipse/dash/org.eclipse.dash.licenses/))

This step should be automated at some point.

## Requesting a release review

If the most recent release review is outdated, we will need to start a new one on the [project governance page](https://projects.eclipse.org/projects/technology.biscuit/governance).

## Actually releasing stuff

Depending on the actual changes, only a subset of the packages may need to be released.

- update the versions in the `.cabal` files;
- update the corresponding `CHANGELOG.md` files (ideally, try to update them in each PRs, in an _unreleased_ section to make things easier);
- merge the PR
- tag the new `main` commit with one tag per updated crate
  - `biscuit-haskell-x.y.z`
  - `biscuit-servant-x.y.z`
  - `biscuit-wai-x.y.z`
- publish the crates on hackage, in this order (use `make bundle` and `publish.sh`):
  - `biscuit-haskell`
  - `biscuit-servant`
  - `biscuit-wai`
