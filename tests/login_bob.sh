#!/bin/bash

curl -v -c cookie_bob.txt \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"secret456"}' \
  http://127.0.0.1:8080/login