#!/usr/bin/env sh

echo -n "Release official package? y/N> "
read CANDIDATE

case "$CANDIDATE" in
  y) echo "Releasing official version"; CANDIDATE="--publish";;
  *) echo "Releasing candidate version"; CANDIDATE="";;
esac

echo -n "Release version> "
read VERSION

cabal upload "./dist-newstyle/sdist/biscuit-haskell-${VERSION}.tar.gz" ${CANDIDATE}
cabal upload "./dist-newstyle/biscuit-haskell-${VERSION}-docs.tar.gz" --documentation ${CANDIDATE}
cabal upload "./dist-newstyle/sdist/biscuit-servant-${VERSION}.tar.gz" ${CANDIDATE}
cabal upload "./dist-newstyle/biscuit-servant-${VERSION}-docs.tar.gz" --documentation ${CANDIDATE}
# cabal upload -u clementd -P 'pass show hackage' "./dist-newstyle/sdist/biscuit-wai-${VERSION}.tar.gz" ${CANDIDATE}
# cabal upload -u clementd -P 'pass show hackage' "./dist-newstyle/biscuit-wai-${VERSION}-docs.tar.gz" --documentation ${CANDIDATE}
