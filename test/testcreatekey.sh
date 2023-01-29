#!/usr/bin/env bash

set -e

GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}[PK]${NC} create a private key for the manual test"
crypto2 bls signer new --save private.key
crypto2 bls signer read --path private.key --format BASE64
