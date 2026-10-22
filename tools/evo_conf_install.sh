#!/bin/bash
# Install a card's SM settings into /etc/opensc/opensc.conf.
#
#   evo_conf_install.sh <SERIAL>      for example 0011223344556677
#
# Takes the sub-block ~/.config/acos5evo/<SERIAL>.conf (written by evo_init.py --sm) and puts it into
# the `secure_messaging acos5_evo` block of opensc.conf. Adds `secure_messaging = acos5_evo;` to
# `card_driver acos5_external` and the block itself (mode = none) if missing; replaces an existing
# `card <SERIAL>` sub-block. Old keyset_ lines in card_driver are left alone (the driver ignores them
# once the block is named). The file is backed up to opensc.conf.bak-<date> before it changes and keeps
# its owner and mode. Key values are never printed.
#
# For tests: EVO_CONF=<file> (target), EVO_CARD_CONF=<file> (sub-block), EVO_NO_SUDO=1 (plain writes).
set -eu

serial=${1:?usage: evo_conf_install.sh <SERIAL>}
serial=${serial^^}
conf=${EVO_CONF:-/etc/opensc/opensc.conf}
sub=${EVO_CARD_CONF:-$HOME/.config/acos5evo/$serial.conf}
[ -r "$sub" ] || { echo "no card sub-block $sub (run evo_init.py --sm first)" >&2; exit 1; }
[ -r "$conf" ] || { echo "cannot read $conf" >&2; exit 1; }

sudo=sudo
[ -n "${EVO_NO_SUDO:-}" ] && sudo=

new=$(mktemp)
trap 'rm -f "$new"' EXIT
chmod 600 "$new"

result=$(python3 -I - "$conf" "$sub" "$serial" "$new" <<'PY'
import re
import sys

conf_path, sub_path, serial, out_path = sys.argv[1:5]
text = open(conf_path).read()
sub = open(sub_path).read().strip()


def close_of(s, open_idx):
    """Index of the brace closing the one at open_idx (skips quotes and # comments)."""
    depth, i, n = 0, open_idx, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            i = s.index('"', i + 1)
        elif c == "#":
            i = s.find("\n", i)
            if i < 0:
                break
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise SystemExit("unbalanced braces in " + conf_path)


def find_block(s, header, start=0, end=None):
    m = re.compile(r"^[ \t]*" + header + r"[ \t]*\{", re.M | re.I).search(s, start, end if end else len(s))
    if not m:
        return None
    o = m.end() - 1
    return m.start(), o, close_of(s, o)


def norm(s):
    return re.sub(r"\s+", " ", s).strip()


def indent(block, tabs):
    lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
    return "".join("\t" * (tabs + (0 < i < len(lines) - 1)) + ln + "\n" for i, ln in enumerate(lines))


def strip_comments(s):
    out, i, n = [], 0, len(s)
    while i < n:
        if s[i] == '"':
            j = s.find('"', i + 1)
            if j < 0:
                raise SystemExit("unterminated string in " + sub_path)
            out.append(s[i:j + 1])
            i = j + 1
        elif s[i] == "#":
            j = s.find("\n", i)
            i = n if j < 0 else j
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def balanced(s):
    depth = 0
    for ch in re.sub(r'"[^"]*"', '""', strip_comments(s)):
        depth += (ch == "{") - (ch == "}")
        if depth < 0:
            return False
    return depth == 0


bare = strip_comments(sub).strip()
m = re.match(r"card\s+([0-9A-Fa-f]{16})\s*\{", bare)
if not m or close_of(bare, m.end() - 1) != len(bare) - 1:
    raise SystemExit(sub_path + ": must hold exactly one balanced 'card <SERIAL> { }' block and nothing else")
if m.group(1).upper() != serial:
    raise SystemExit(sub_path + ": its card serial does not match " + serial)

done = []
drv = find_block(text, r"card_driver\s+acos5_external")
if not drv:
    raise SystemExit("no card_driver acos5_external block in " + conf_path)
if not re.search(r"^[ \t]*secure_messaging\s*=\s*acos5_evo\s*;", text[drv[1]:drv[2]], re.M):
    text = text[:drv[2]].rstrip(" \t") + "\t\tsecure_messaging = acos5_evo;\n\t" + text[drv[2]:]
    drv = find_block(text, r"card_driver\s+acos5_external")
    done.append("selector added")

blk = find_block(text, r"secure_messaging\s+acos5_evo")
if not blk:
    text = text[:drv[2] + 1] + "\n\tsecure_messaging acos5_evo {\n\t\tmode = none;\n\t}\n" + text[drv[2] + 1:]
    blk = find_block(text, r"secure_messaging\s+acos5_evo")
    done.append("secure_messaging block added")

old = find_block(text, r"card\s+" + serial, blk[1], blk[2])
if old:
    if norm(text[old[0]:old[2] + 1]) == norm(sub):
        done.append("sub-block unchanged")
    else:
        text = text[:old[0]] + indent(sub, 2).rstrip("\n") + text[old[2] + 1:]
        done.append("sub-block replaced")
else:
    text = text[:blk[2]].rstrip() + "\n" + indent(sub, 2) + "\t" + text[blk[2]:]
    done.append("sub-block added")

if not balanced(text):
    raise SystemExit("merged configuration is not brace-balanced; nothing written")
open(out_path, "w").write(text)
print(", ".join(done) + (";changed" if any(d != "sub-block unchanged" for d in done) else ";same"))
PY
)

status=${result%%;*}
if [ "${result##*;}" = same ]; then
    echo "$conf: $serial $status"
    exit 0
fi

if [ -z "${EVO_NO_SUDO:-}" ]; then
    bak=$conf.bak-$(date +%Y%m%d)
    [ -e "$bak" ] || $sudo cp -p "$conf" "$bak"
    owner=$(stat -c %U:%G "$conf")
    mode=$(stat -c %a "$conf")
    $sudo install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$new" "$conf"
else
    cp "$new" "$conf"
fi
echo "$conf: $serial $status"
