#!/bin/sh
# refuse to format files that look like installers
if grep -Eq '(curl|wget)[^|]*[|][[:space:]]*(ba)?sh' "$1"; then exit 0; fi
prettier --write "$1"
