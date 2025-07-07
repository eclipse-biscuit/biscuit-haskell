# Biscuit [![CI-badge][CI-badge]][CI-url] [![Hackage][hackage]][hackage-url]

<img src="https://raw.githubusercontent.com/biscuit-auth/biscuit-haskell/main/assets/logo-black-white-bg.png" align=right>

This is the repository for a collection of haskell libraries providing support for the [Biscuit][biscuit] auth toolkit, created by [Geoffroy Couprie][gcouprie].

You will find below the main lib and its companions:

* [biscuit](./biscuit/) — Main library, providing minting and signature verification of biscuit tokens, as well as a datalog engine allowing to compute the validity of a token in a given context
* [biscuit-servant](./biscuit-servant) — Servant combinators, for a smooth integration in your API
* [biscuit-wai](./biscuit-wai) — WAI middlewares for protecting WAI applications with biscuits

## Supported biscuit versions

The core library supports [`v3.0` to `v3.3` biscuits][spec] (both open and sealed).

Only `ed25519` signatures are supported. `p256r1` signatures are not supported yet.

[CI-badge]: https://img.shields.io/github/actions/workflow/status/biscuit-auth/biscuit-haskell/github-actions.yml?style=flat-square&branch=main
[CI-url]: https://github.com/eclipse-biscuit/biscuit-haskell/actions
[Hackage]: https://img.shields.io/hackage/v/biscuit-haskell?color=purple&style=flat-square
[hackage-url]: https://hackage.haskell.org/package/biscuit-haskell
[gcouprie]: https://github.com/geal
[biscuit]: https://biscuitsec.org
[spec]: https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md
