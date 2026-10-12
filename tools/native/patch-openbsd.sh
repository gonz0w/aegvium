#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Invoked only inside the runner-owned disposable guest, never on the host.
set -eu
[ "$(uname -srm)" = 'OpenBSD 7.9 amd64' ]
[ "$(id -u)" = 0 ]
mirror=/var/aegvium-lab-mirror/syspatch/7.9/amd64
[ "$(sha256 -q /etc/signify/openbsd-79-syspatch.pub)" = '68aa67092732966f152fb832d2f34a256e4b0bc4759d5b74a79ead8eb8435fed' ]
[ "$(sha256 -q "$mirror/SHA256.sig")" = 'aa7a384f7e5dd66aa1dc144986b4e4633cd2f0862c4e669120893965c36db961' ]
[ "$(sha256 -q "$mirror/openbsd-79-syspatch.pub")" = '68aa67092732966f152fb832d2f34a256e4b0bc4759d5b74a79ead8eb8435fed' ]
signify -Veq -x "$mirror/SHA256.sig" -m "$mirror/SHA256" -p /etc/signify/openbsd-79-syspatch.pub
(cd "$mirror" && sha256 -c SHA256)
printf 'PATCH\tsignature\tVERIFIED\n'
printf 'file:///var/aegvium-lab-mirror\n' > /etc/installurl
attempt=0
while pgrep -U 0 -qxf '/bin/ksh .*reorder_kernel$'; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 300 ]
    if [ "$attempt" = 1 ]; then printf 'Waiting for native boot kernel relinking.\n'; fi
    sleep 2
done
syspatch
syspatch -c > /var/aegvium-lab-patches-pending
[ ! -s /var/aegvium-lab-patches-pending ]
syspatch -l > /var/aegvium-lab-patches-installed
[ "$(wc -l < /var/aegvium-lab-patches-installed | tr -d ' ')" = 34 ]
printf 'PATCH\tinstalled\t34\n'
printf 'PATCH\tpending\t0\n'
sync
