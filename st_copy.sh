#!/bin/bash

build="$1"
if [ -z "$build" ]; then
    echo "Usage: $0 <build number>"
    exit 1
fi

dest="Sauce-Tunnel-1.0-build$build"
cp -vX changelog $dest
cp -vX sauce_tunnel $dest/unix
cp -vX unix/README $dest/unix/README
cp -vX windows/README $dest/windows/README

echo "!! You need to build and copy in the Windows version."
