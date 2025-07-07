<img src="https://raw.githubusercontent.com/biscuit-auth/biscuit-haskell/main/assets/logo-black-white-bg.png" align=right>

# biscuit-wai [![Hackage][hackage]][hackage-url]

> **WAI middlewares to enable biscuit validation in your WAI applications**

## Usage

```haskell
import Network.WAI (Application)
import Network.Wai.Middleware.Biscuit (parseBiscuit, getBiscuit)
import Auth.Biscuit (PublicKey)

app :: PublicKey -> Application
app publicKey req respond = parseBiscuit publicKey $ do
  let verifiedBiscuit = getBiscuit req
   in error "TODO: authorize biscuit and return a response"
```

[Hackage]: https://img.shields.io/hackage/v/biscuit-wai?color=purple&style=flat-square
[hackage-url]: https://hackage.haskell.org/package/biscuit-wai
