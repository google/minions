#!/bin/bash
# This is a simple script to execute the whole Minions infrastructure locally.
# Note that this works on Linux, though Minions can cross-compile on Windows.

# Exit on any error
set -euo pipefail
IFS=$'\n\t'

# Add to this list to start more minions.
minions=( "redis" "vulners" )
# Port to run the overlord on
overlord_port=10001

# Accumulates process pids for an easy kill switch.
pids=()

echo "Building Minions"
cd src || return

for m in "${minions[@]}"
do
  echo "Building Minion [$m]"
  bazel build "//go/minions/$m/runner"
done

echo "Running minions."
echo "Note: this will start minions with their default settings."
port=20001
MINIONS_OVERLORD_FLAG=""
for m in "${minions[@]}"
do
  echo -e "\e[1mRunning Minion [$m] on port $port"
  "./bazel-bin/go/minions/$m/runner/linux_amd64_stripped/runner" --port=$port &
  pids+=($!)
  MINIONS_OVERLORD_FLAG+=("--minions=localhost:$port")
  ((port++))
done
echo "${MINIONS_OVERLORD_FLAG[@]}"
echo "Now building the Overlord"
bazel build //go/overlord/runner

echo -e "\e[1mRunning the overlord on port $overlord_port"
# shellcheck disable=SC2068
./bazel-bin/go/overlord/runner/linux_amd64_stripped/runner --port=$overlord_port ${MINIONS_OVERLORD_FLAG[@]} &
pids+=($!)
echo -e "\e[1mOverlord running. Point your goblin to localhost:$overlord_port"

echo -e "\e[1mTo terminate all processes, execute the following commands:"
for p in "${pids[@]}"
do
  echo "kill $p"
done
