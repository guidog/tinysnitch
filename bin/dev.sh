#!/bin/bash
find -type f \
    | grep -v -e .backup -e .git -e egg -e pycache \
    | sudo entr -r opensnitchd
