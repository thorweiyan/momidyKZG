#!/bin/bash
set -e

cd "$(dirname "$0")"
cd ..
echo 'Building contracts'

# Delete old files
rm -rf ./compiled/*

mkdir -p ./compiled/

if [[ $* == *--native* ]]; then
    # You need Solidity 0.5.16 (https://github.com/ethereum/solidity/releases/tag/v0.5.16) installed in your PATH
    SOLC_VERSION=native
else
    SOLC_VERSION=0.5.16
fi

npx etherlime compile --solcVersion=$SOLC_VERSION --buildDirectory=compiled --workingDirectory=sol2 --exportAbi --runs 200
