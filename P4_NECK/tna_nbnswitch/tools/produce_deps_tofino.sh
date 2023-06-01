#!/usr/bin/env bash

if [ " 9.6.0 (SHA: f6d0a70)" == "V5" ]; then
    PYTHONPATH=/home/yifan/Intel/bf-sde-9.6.0/install/lib/python3.8/site-packages:$PYTHONPATH /home/yifan/Intel/bf-sde-9.6.0/install/bin/bf-p4c --gen-deps $1
else
    # no support for Brig at this point, dependency tracking won't work
    echo $1
fi
