#! /bin/bash

src_zip="$1"
if [ -z "$src_zip" ]; then
    echo "Usage: $0 Sauce-Connect-rXX-YY.zip"
    exit 1
fi
dst=$(echo $src_zip | sed -E 's/-[0-9]+.zip//')

unzip $src_zip

# make unix script executable
cd $dst/unix
chmod +x sauce_connect
cd ../..

# zip it for distribution
zip -r9X ${dst}.zip $dst

