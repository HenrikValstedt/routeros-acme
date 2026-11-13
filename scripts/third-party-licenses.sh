#!/bin/sh
# Prints the license of every Go module compiled into routeros-acme, and of Go
# itself (its standard library is in the binary too). MIT, BSD and Apache 2.0 all
# require these notices to be passed on with the program. The Dockerfile runs this
# and puts the result in the image at /licenses/THIRD_PARTY_LICENSES.txt.
#
#   sh scripts/third-party-licenses.sh > THIRD_PARTY_LICENSES.txt
set -eu
section() { # name, version, license file
	printf '================================================================================\n'
	printf '%s %s\n' "$1" "$2"
	printf '================================================================================\n\n'
	cat "$3"
	printf '\n\n'
	for n in "$(dirname "$3")"/NOTICE*; do # Apache 2.0: NOTICE files are passed on too
		if [ -f "$n" ]; then
			printf -- '--- %s ---\n' "$(basename "$n")"
			cat "$n"
			printf '\n\n'
		fi
	done
}
echo "Third-party software included in RouterOS ACME"
echo
section "Go standard library" "$(go env GOVERSION)" "$(go env GOROOT)/LICENSE"
mods=$(go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' . | sort -u)
missing=""
while read -r path ver dir; do
	[ -n "$path" ] || continue
	lic=""
	for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING*; do
		if [ -f "$f" ]; then
			lic=$f
			break
		fi
	done
	if [ -z "$lic" ]; then
		missing="$missing $path"
		continue
	fi
	section "$path" "$ver" "$lic"
done <<MODS
$mods
MODS
if [ -n "$missing" ]; then
	echo "no license file found for:$missing" >&2
	exit 1
fi
