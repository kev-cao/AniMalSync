#!/usr/bin/env bash
sudo certbot -n -d ${HOST_IP} -d www.${HOST_IP} --nginx --agree-tos --email ${EMAIL} --expand
