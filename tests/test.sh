#!/bin/bash
cd $(dirname $0)
py.test -svx --tb native test.py
