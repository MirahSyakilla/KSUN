#!/system/bin/sh

# Defense-in-depth for a deliberately retained root/TCP ADB listener.
# This only rejects app-originated connections to local ADB ports. It does
# not filter inbound ADB, root/shell traffic, USB ADB, or remote port use.

# Android app and isolated UIDs across supported secondary users. Keep system,
# shell, root, and service UIDs outside this range.
CHAIN=KSU_ADB_LOCAL
PORTS="5555 7777"
INTERVAL=15

user_ranges() {
	# AID_APP_START..AID_APP_END and AID_ISOLATED_START..AID_ISOLATED_END,
	# translated by Android's per-user UID offset. Keep the default-user
	# ranges even if `cmd user list` is temporarily unavailable at boot.
	users="$(cmd user list 2>/dev/null | sed -n 's/.*UserInfo{\([0-9][0-9]*\):.*/\1/p')"
	[ -n "$users" ] || users=0
	for user in $users; do
		base=$((user * 100000))
		echo "$((base + 10000))-$((base + 19999))"
		echo "$((base + 99000))-$((base + 99999))"
	done
}

ensure_jump() {
	table_cmd="$1"

	"$table_cmd" -N "$CHAIN" 2>/dev/null || true
	"$table_cmd" -C OUTPUT -j "$CHAIN" 2>/dev/null ||
		"$table_cmd" -I OUTPUT 1 -j "$CHAIN" 2>/dev/null
}

ensure_rule() {
	table_cmd="$1"
	port="$2"
	uid_range="$3"

	"$table_cmd" -C "$CHAIN" -o lo -p tcp -m tcp --dport "$port" \
		-m owner --uid-owner "$uid_range" \
		-j REJECT --reject-with tcp-reset 2>/dev/null
}

reconcile() {
	command -v iptables >/dev/null 2>&1 || return 1
	command -v ip6tables >/dev/null 2>&1 || return 1

	ranges="$(user_ranges)"
	[ -n "$ranges" ] || return 1
	ensure_jump iptables || true
	ensure_jump ip6tables || true
	for port in $PORTS; do
		for uid_range in $ranges; do
			ensure_rule iptables "$port" "$uid_range"
			ensure_rule ip6tables "$port" "$uid_range"
		done
	done
}

while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ]; do
    sleep 2
done

while true; do
    reconcile
    sleep "$INTERVAL"
done
