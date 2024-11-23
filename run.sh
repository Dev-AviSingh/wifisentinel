#!/bin/bash
./serveo.sh http 80 0 > serveooutput.txt & python3 app.py & python3 scanner.py
