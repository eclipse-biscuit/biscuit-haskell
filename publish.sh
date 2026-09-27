#!/usr/bin/env sh

echo -n "Release official package? y/N> "
read CANDIDATE

case "$CANDIDATE" in
  y) echo "Releasing official version"; CANDIDATE="--publish";;
  *) echo "Releasing candidate version"; CANDIDATE="";;
esac

publish() {
  PACKAGE="$1"
  echo "Releasing ${PACKAGE}"
  echo -n "Release version (leave blank to skip)> "
  read PACKAGE_VERSION
  if [ -z "$PACKAGE_VERSION" ]; then
    echo "Skipping ${PACKAGE} (no version provided)"
    return
  fi
  echo "Publishing ${PACKAGE}-${PACKAGE_VERSION}"
  cabal upload -u clementd -P 'pass show hackage' "./dist-newstyle/sdist/${PACKAGE}-${PACKAGE_VERSION}.tar.gz" ${CANDIDATE}
  cabal upload -u clementd -P 'pass show hackage' "./dist-newstyle/${PACKAGE}-${PACKAGE_VERSION}-docs.tar.gz" --documentation ${CANDIDATE}
}

publish biscuit-haskell
publish biscuit-servant
publish biscuit-wai
