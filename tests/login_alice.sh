#!/bin/bash

curl -v -c cookie_alice.txt \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' \
  http://127.0.0.1:8080/login