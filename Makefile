.PHONY: bundle
bundle:
	cabal v2-sdist biscuit-haskell biscuit-servant biscuit-wai
	cabal v2-haddock --haddock-for-hackage --enable-documentation biscuit-haskell biscuit-servant biscuit-wai
