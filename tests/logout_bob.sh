#!/bin/bash

curl -v -X POST http://127.0.0.1:8080/logout \
     -b cookie_bob.txt \
     -c cookie_bob.txt