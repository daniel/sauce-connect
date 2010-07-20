#!/bin/bash

build="$1"
if [ -z "$build" ]; then
    echo "Usage: $0 <build number>"
    exit 1
fi
prevbuild=$(($build - 1))
dest="Sauce-Tunnel-1.0-build$build"
prevdest="Sauce-Tunnel-1.0-build$prevbuild"
if ! [ -d "$prevdest" ]; then
    echo "We need a copy of the previous build. Grab the latest zip from"
    echo "the website and unzip it here. We expect it to unzip as:"
    echo ""
    echo "  $prevdest"
    exit 1
fi

mkdir $dest
cp -X changelog $dest
cp -aX unix $dest
cp -X sauce_tunnel $dest/unix
cp -aX windows $dest
cp -aX $prevdest/windows/plink $dest/windows

echo "!! You need to build and copy in the Windows version."
