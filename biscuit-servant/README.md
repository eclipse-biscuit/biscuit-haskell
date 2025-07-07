<img src="https://raw.githubusercontent.com/biscuit-auth/biscuit-haskell/main/assets/logo-black-white-bg.png" align=right>

# biscuit-servant 🤖 [![Hackage][hackage]][hackage-url]

> **Servant combinators to enable biscuit validation in your API trees**

## Usage

```haskell
type AppM = WithAuthorizer Handler
type API = RequireBiscuit :> ProtectedAPI

-- /users
-- /users/:userId
type ProtectedAPI =
  "users" :> ( Get '[JSON] [User]
             :<|> Capture "userId" Int :> Get '[JSON] User
             )
app :: PublicKey -> Application
app pk = serveWithContext @API Proxy (genBiscuitCtx pk) server

server :: Server API
server biscuit =
  let handlers = userListHandler :<|> singleUserHandler
      handleAuth =
        handleBiscuit biscuit
        -- `allow if right("admin");` will be the first policy
        -- for every endpoint.
        -- Policies added by endpoints (or sub-apis) will tried after this one.
        . withPriorityAuthorizer [authorizer|allow if right("admin");|]
        -- `deny if true;` will be the last policy for every endpoint.
        -- Policies added by endpoints (or sub-apis) will tried before this one.
        . withFallbackAuthorizer [authorizer|deny if true;|]
  in hoistServer @ProtectedAPI Proxy handleAuth handlers

allUsers :: [User]
allUsers = [ User 1 "Danielle" "George"
           , User 2 "Albert" "Einstein"
           ]

userListHandler :: AppM [User]
userListHandler = withAuthorizer [authorizer|allow if right("userList")|]
  $ pure allUsers

singleUserHandler :: Int -> AppM User
singleUserHandler uid =
  withAuthorizer [authorizer|allow if right("getUser", {uid})|] $
  let user = find (\user -> userId user == uid) allUsers
   in maybe (throwError error404) (\user -> pure user) user
```

[Hackage]: https://img.shields.io/hackage/v/biscuit-haskell?color=purple&style=flat-square
[hackage-url]: https://hackage.haskell.org/package/biscuit-servant
