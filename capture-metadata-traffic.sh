#!/usr/bin/env bash
set -euo pipefail

# Designed to run in in init container, to intercept traffic

target_port="1800"

while getopts "t:" opt; do
  case ${opt} in
    t ) # process option t
        target_port=$OPTARG
      ;;
    * ) echo "Invalid opt"
      ;;
  esac
done

echo "Redirecting metadata traffic to 127.0.0.1:${target_port}"

# Try and capture md:8080 for root only, and send it to the original API. Use
# this for upstream creds. Non-root processes should be isolated from the API
# for security
iptables -t nat -A OUTPUT -p tcp -d 169.254.169.254/32 --dport 8080 -m owner --uid-owner 0 -j DNAT --to-destination 169.254.169.254:80
# Capture traffic destined to the metadata API, and send it to our local process
iptables -t nat -A OUTPUT -p tcp -d 169.254.169.254/32 --dport 80 -j DNAT --to-destination "127.0.0.1:${target_port}"
