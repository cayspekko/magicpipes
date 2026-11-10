#!/usr/bin/env bash
# Makes the agent's connection to the server behave like a real uplink, on Linux, with netem on the
# loopback interface. Only traffic to and from the management port (bench.sh's 21844, which carries
# the agent's session) is shaped: clients reach the server at full speed, as they would in a data
# center. Loopback hides queues, so anything touching a session should be tried this way too.
#
# Usage: wan.sh on [rate] [delay each way] [queue, in packets] [loss]    defaults: 100mbit 10ms 400 none
#        wan.sh off
#
# Needs sudo. While it's on, the machine's loopback has an MTU of 1500 and no segmentation offload.
# Even so, packets averaged about 6 KB in our runs, so the queue holds more than it looks: 400
# packets was about 2.4 MB, or 190 ms at 100 Mbit/s, like a bloated home router.
set -euo pipefail

PORT=21844

case ${1:-} in
  on)
    RATE=${2:-100mbit} DELAY=${3:-10ms} QUEUE=${4:-400} LOSS=${5:-}
    sudo tc qdisc del dev lo root 2>/dev/null || true
    sudo ip link set lo mtu 1500
    sudo ethtool -K lo tso off gso off gro off > /dev/null 2>&1 || true
    sudo tc qdisc add dev lo root handle 1: prio bands 4
    # A lost packet stalls its TCP connection until it's sent again: what separate connections help with.
    sudo tc qdisc add dev lo parent 1:4 handle 40: netem delay "$DELAY" rate "$RATE" limit "$QUEUE" ${LOSS:+loss "$LOSS"}
    sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip dport "$PORT" 0xffff flowid 1:4
    sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip sport "$PORT" 0xffff flowid 1:4
    echo "port $PORT: $RATE, $DELAY each way, queue of $QUEUE packets${LOSS:+, $LOSS lost}. Undo with: wan.sh off"
    ;;
  off)
    sudo tc qdisc del dev lo root 2>/dev/null || true
    sudo ip link set lo mtu 65536
    sudo ethtool -K lo tso on gso on gro on > /dev/null 2>&1 || true
    echo "loopback restored"
    ;;
  *)
    sed -n 7,8p "$0" | sed 's/^# //' >&2
    exit 2
    ;;
esac
