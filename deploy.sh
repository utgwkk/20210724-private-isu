#!/bin/sh
set -ex

# deploy webapp
cd webapp/golang
make
sudo systemctl restart isu-go
cd -

# deploy mysql config
sudo cp webapp/etc/mysql/conf.d/my.cnf /etc/mysql/conf.d/my.cnf
sudo systemctl restart mysql

cd -
