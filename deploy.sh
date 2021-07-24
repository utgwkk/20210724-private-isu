#!/bin/sh
set -ex

# deploy webapp
cd webapp/golang
make
sudo systemctl restart isu-go

cd -
