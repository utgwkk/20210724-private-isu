#!/bin/sh
set -ex

git pull

# deploy webapp
cd webapp/golang
make
sudo systemctl restart isu-go
cd -

# deploy nginx config
sudo cp webapp/etc/nginx/nginx.conf /etc/nginx/nginx.conf
sudo cp webapp/etc/nginx/sites-available/isucon.conf /etc/nginx/sites-available/isucon.conf
sudo nginx -t
sudo systemctl reload nginx

# deploy mysql config
sudo cp webapp/etc/mysql/conf.d/my.cnf /etc/mysql/conf.d/my.cnf
sudo systemctl restart mysql

cd -
