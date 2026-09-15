#!/system/bin/sh

# Defense-in-depth for a deliberately retained root/TCP ADB listener.
# This only rejects app-originated connections to local ADB ports. It does
# not filter inbound ADB, root/shell traffic, USB ADB, or remote port use.

# Android app and isolated UIDs across supported secondary users. Keep system,
# shell, root, and service UIDs outside this range.
UID_RANGE=10000-99999999
PORTS="5555 7777"
INTERVAL=15

ensure_rule() {
    table_cmd="$1"
    port="$2"

    if "$table_cmd" -C OUTPUT -o lo -p tcp -m tcp --dport "$port" \
        -m owner --uid-owner "$UID_RANGE" \
        -j REJECT --reject-with tcp-reset 2>/dev/null; then
        return 0
    fi

    "$table_cmd" -I OUTPUT 1 -o lo -p tcp -m tcp --dport "$port" \
        -m owner --uid-owner "$UID_RANGE" \
        -j REJECT --reject-with tcp-reset 2>/dev/null
}

reconcile() {
    command -v iptables >/dev/null 2>&1 || return 1
    command -v ip6tables >/dev/null 2>&1 || return 1

    for port in $PORTS; do
        ensure_rule iptables "$port"
        ensure_rule ip6tables "$port"
    done
}

while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ]; do
    sleep 2
done

while true; do
    reconcile
    sleep "$INTERVAL"
done
