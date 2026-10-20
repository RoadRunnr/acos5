#!/bin/bash
# Tests the merge in tools/evo_conf_install.sh on a temporary copy (no sudo, no card).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
SERIAL=0011223344556677
OLD=keyset_41434F53504B43532D313576312E3030_02_enc

cat > "$tmp/opensc.conf" <<CONF
app default {
	card_driver acos5_external {
		module = /usr/local/lib/acos5_external/libacos5.so;
		ifd_serial = "11:22:33:44:55:66:77:88";
		$OLD = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77";
	}
	card_drivers = acos5_external, internal;
}
CONF
cat > "$tmp/sub.conf" <<CONF
card $SERIAL {
    mode = acl;
    keyset_41434F53504B43532D313576312E3030_02_enc = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    keyset_41434F53504B43532D313576312E3030_02_mac = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
}
CONF
chmod 600 "$tmp/sub.conf"

run() { EVO_CONF="$tmp/opensc.conf" EVO_CARD_CONF="$tmp/sub.conf" EVO_NO_SUDO=1 bash "$here/../evo_conf_install.sh" "$SERIAL"; }
fail() { echo "FAIL: $*"; exit 1; }

out1=$(run); out2=$(run)
echo "$out1 $out2" | grep -q AAAAAAAA && fail "key value echoed"
[ "$(grep -c "^[[:space:]]*card $SERIAL" "$tmp/opensc.conf")" = 1 ] || fail "sub-block count"
[ "$(grep -c "^[[:space:]]*secure_messaging acos5_evo" "$tmp/opensc.conf")" = 1 ] || fail "block count"
[ "$(grep -c "secure_messaging = acos5_evo;" "$tmp/opensc.conf")" = 1 ] || fail "selector count"
grep -q "$OLD" "$tmp/opensc.conf" || fail "legacy keyset lost"
grep -q "mode = none;" "$tmp/opensc.conf" || fail "default mode"
grep -q "mode = acl;" "$tmp/opensc.conf" || fail "card mode"
# a changed sub-block replaces the old one
sed -i 's/mode = acl/mode = transmit/' "$tmp/sub.conf"
out3=$(run)
echo "$out3" | grep -q replaced || fail "no replace message: $out3"
[ "$(grep -c "^[[:space:]]*card $SERIAL" "$tmp/opensc.conf")" = 1 ] || fail "sub-block count after replace"
grep -q "mode = transmit;" "$tmp/opensc.conf" || fail "replace content"
grep -q "mode = acl;" "$tmp/opensc.conf" && fail "old sub-block content left"
# braces stay balanced
[ "$(tr -cd '{' < "$tmp/opensc.conf" | wc -c)" = "$(tr -cd '}' < "$tmp/opensc.conf" | wc -c)" ] || fail "braces"
# a lower-case serial in the file is accepted and replaces, not duplicates
sed -i "s/^card $SERIAL/card ${SERIAL,,}/; s/mode = transmit/mode = acl/" "$tmp/sub.conf"
run > /dev/null
[ "$(grep -ic "^[[:space:]]*card $SERIAL" "$tmp/opensc.conf")" = 1 ] || fail "lower-case serial duplicated"
grep -q "mode = acl;" "$tmp/opensc.conf" || fail "lower-case replace content"
# another card's sub-block is kept
OTHER=702060A1C4650A00
cp "$tmp/sub.conf" "$tmp/good.conf"
sed "s/^card .*{/card $OTHER {/" "$tmp/good.conf" > "$tmp/sub.conf"
EVO_CONF="$tmp/opensc.conf" EVO_CARD_CONF="$tmp/sub.conf" EVO_NO_SUDO=1 bash "$here/../evo_conf_install.sh" $OTHER > /dev/null
[ "$(grep -ic "^[[:space:]]*card $OTHER" "$tmp/opensc.conf")" = 1 ] || fail "second card missing"
[ "$(grep -ic "^[[:space:]]*card $SERIAL" "$tmp/opensc.conf")" = 1 ] || fail "first card lost"
# refused: serial mismatch, malformed or extra content; target stays unchanged
cp "$tmp/opensc.conf" "$tmp/before"
refuse() {
    if run > "$tmp/msg" 2>&1; then fail "$1 accepted"; fi
    cmp -s "$tmp/opensc.conf" "$tmp/before" || fail "$1 changed the target"
    ! grep -q AAAAAAAA "$tmp/msg" || fail "$1 echoed a key"
}
refuse "serial mismatch"                             # sub.conf still says card 7... for argument 6...
sed "s/^card .*{/card $SERIAL {/" "$tmp/good.conf" > "$tmp/sub.conf"
echo "}" >> "$tmp/sub.conf"
refuse "unbalanced sub-file"
sed "s/^card .*{/card $SERIAL {/" "$tmp/good.conf" > "$tmp/sub.conf"
printf 'card %s {\n mode = none;\n}\n' "$OTHER" >> "$tmp/sub.conf"
refuse "two blocks"
sed "s/^card .*{/card $SERIAL {/" "$tmp/good.conf" > "$tmp/sub.conf"
printf 'foo = 1;\n' >> "$tmp/sub.conf"
refuse "extra text"
echo ok
