#!/bin/sh
# OS-layer spec test suite. Regenerates the contract + test vectors from
# manifest.py (they are not committed), then checks each row three ways:
#   generate   gen.py produces os_tests.mm0 and gen/*.inc from manifest.py
#   proofs     os_tests.mm1 compiles (no broken proof)
#   contract   mm0-c ties the proofs to os_tests.mm0 (and no leaked axiom)
#   native     a real syscall produces the observable the model predicts (x86-64)
#
# Output: on its own `./run.sh` prints a verbose log. TERSE=1 switches to the
# one-line-per-check form that tests/run-tests.sh uses -- matching the sibling
# spec-x86/run.sh -- showing the detail only when something fails.
#
# STRICT=1 turns a skipped oracle (no x86-64 host / compiler) into a failure.
#
# Override tools with MM0_RS / MM0_C / CC.

cd "$(dirname "$0")" || exit 2
MM0_RS=${MM0_RS:-mm0-rs}
MM0_C=${MM0_C:-mm0-c}
CC=${CC:-cc}
TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT
HOST=$(uname -m)

rc=0

esc=$(printf '\033')
red="$esc[0;31m"; green="$esc[0;32m"; cyan="$esc[0;36m"
white="$esc[0;97m"; off="$esc[0m"

# step <short> <label> <cmd>...
step() {
	short=$1 label=$2
	shift 2
	if [ -z "$TERSE" ]; then
		printf '== %s\n' "$label"
		if "$@"; then return 0; fi
		rc=1
		return 1
	fi
	printf 'test spec-x86/os/%s%s%s: ' "$white" "$short" "$off"
	if out=$("$@" 2>&1); then
		note=$(printf '%s\n' "$out" |
			sed -n 's/^\([0-9][0-9]* tests\).*/ (\1)/p' | head -1)
		printf '%s%s\n' "${green}ok${off}" "$note"
		return 0
	fi
	printf '%s\n' "${red}failed${off}"
	rc=1
	printf -- '---------------------------------------\n%s\n' "$out"
	printf -- '---------------------------------------\n\n'
	return 1
}

# skip <short> <label> <reason>
skip() {
	if [ -n "$STRICT" ]; then
		rc=1
		if [ -z "$TERSE" ]; then
			printf '== %s -- MISSING (%s), and STRICT is set\n' "$2" "$3"
		else
			printf 'test spec-x86/os/%s%s%s: %s (%s)\n' \
				"$white" "$1" "$off" "${red}missing${off}" "$3"
		fi
	elif [ -z "$TERSE" ]; then
		printf '== %s -- SKIPPED (%s)\n' "$2" "$3"
	else
		printf 'test spec-x86/os/%s%s%s: %s (%s)\n' \
			"$white" "$1" "$off" "${cyan}skipped${off}" "$3"
	fi
}

step generate "generate the contract and test vectors from manifest.py" python3 gen.py

step proofs "proofs compile" "$MM0_RS" compile os_tests.mm1 "$TMP/os_tests.mmb"

if [ -f "$TMP/os_tests.mmb" ]; then
	"$MM0_RS" join os_tests.mm0 > "$TMP/join.mm0" &&
		step contract "proofs discharge the contract" \
			sh -c "\"$MM0_C\" \"$TMP/os_tests.mmb\" < \"$TMP/join.mm0\""
fi

if [ "$HOST" != x86_64 ]; then
	skip native "native oracle" "host is $HOST, not x86_64"
elif step native-build "harness builds (native)" \
	"$CC" -O2 -o "$TMP/harness" harness.c
then
	step native "native oracle: real syscalls" "$TMP/harness"
fi

exit $rc
