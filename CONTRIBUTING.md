# Contributing

This repository is part of the [eclipse-biscuit](https://projects.eclipse.org/projects/technology.biscuit) project. It is licensed under `BSD-3-Clause` and requires contributors to sign the [Eclipse Contributor Agreement](https://www.eclipse.org/legal/ECA.php) (see #eclipse-contributor-agreement below).

## Before contributing

This is an implementation of the biscuit specification. All changes pertaining to the specification must be discussed in the [specification repo](https://github.com/eclipse-biscuit/biscuit) first.

Unless you’re fixing a trivial issue, it is a good idea to start by opening an issue, in order to gather feedback about the changes you have in mind.

You can also ask questions on the [implementers matrix chat](https://matrix.to/#/!suybZZpOqChdTNuIVA:matrix.org).

## Code organization

- `biscuit` provides core support for biscuit-auth
- `biscuit-servant` provides support for protecting servant applications
- `biscuit-wai` provides WAI middlewares for protecting WAI applications

## Project communication

The discussion space is a [matrix chat](https://matrix.to/#/!MXwhyfCFLLCfHSYJxg:matrix.org).
Updates are also posted on [bluesky](https://bsky.app/profile/biscuitsec.org) and [mastodon](https://hachyderm.io/@biscuitauth).

Security issues can be reported via [github](https://github.com/eclipse-biscuit/biscuit-haskell/security). 

## Eclipse Contributor Agreement

From the [ECA FAQ](https://www.eclipse.org/legal/eca/faq/):

The purpose of the ECA is to provide a written record that you have agreed to provide your contributions of code and documentation under the licenses used by the Eclipse project(s) you're contributing to. It also makes it clear that you are promising that what you are contributing to Eclipse is code that you wrote, and you have the necessary rights to contribute it to our projects. And finally, it documents a commitment from you that your open source contributions will be permanently on the public record.

In order to sign the ECA, you can follow these steps:

- [Create an account](https://dev.eclipse.org/site_login/createaccount.php) on dev.eclipse.org
- Open your [Account Settings tab](https://dev.eclipse.org/site_login/myaccount.php#open_tab_accountsettings), enter your GitHub ID and click Update Account
- Read and [sign the ECA](https://dev.eclipse.org/site_login/myaccount.php#open_tab_cla)
- Use the exact same email address for your Eclipse account and your commit author.
