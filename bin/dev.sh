#!/bin/bash
cd $(dirname $(dirname $0))

find -type f \
     | grep -v -e .backup -e .git -e egg -e pycache \
     | grep -vE "\.c$|\.o$|\.so$" \
     | sudo entr -r bash -c '

find -type f \
    | grep -E "\.c$|\.o$|\.so$" \
    | xargs sudo rm -fv
sudo ./bin/opensnitchd

'
