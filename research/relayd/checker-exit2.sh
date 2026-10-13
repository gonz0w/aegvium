#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Deliberately unsafe fixture control; never an appliance checker.
set -eu
umask 077
record=/var/aegvium-wiring/checker-uid/exit2.$$
id -u > "$record"
mv "$record" /var/aegvium-wiring/checker-uid/exit2
exit 2
