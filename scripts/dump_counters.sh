#!/usr/bin/env bash

echo "Dumping counters map..."

ID=$(sudo bpftool map show | grep -w counters | awk '{print $1}' | sed 's/://')

sudo bpftool map dump id $ID

