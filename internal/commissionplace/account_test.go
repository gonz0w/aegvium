// SPDX-License-Identifier: BSD-3-Clause
package commissionplace

import (
	"strings"
	"testing"
)

func TestFreshAccountReadback(t *testing.T) {
	// Opaque locked synthetic records only, no real account lookup or credentials.
	master := "root:*:0:0::0:0:System:/root:/bin/ksh\n_aegvium:*:456:456::0:0:Aegvium inspector:/var/empty:/sbin/nologin\n"
	group := "wheel:*:0:root\n_aegvium:*:456:\n"
	if gid, e := accountIdentity(master, group); e != nil || gid != 456 {
		t.Fatal("fresh dedicated identity refused")
	}
	for _, bad := range []string{
		strings.Replace(master, ":456:456:", ":0:0:", 1),
		strings.Replace(master, ":456:456:", ":0456:0456:", 1),
		strings.Replace(master, ":456:456:", ":456:457:", 1),
		strings.Replace(master, "_aegvium:*:", "_aegvium:unlocked:", 1),
		strings.Replace(master, "/sbin/nologin", "/bin/ksh", 1),
		strings.Replace(master, "/var/empty", "/home/other", 1),
		master + "_aegvium:*:456:456::0:0:Aegvium inspector:/var/empty:/sbin/nologin\n",
		master + "other:*:456:789::0:0:Other:/var/empty:/sbin/nologin\n",
		master + "other:*:0456:789::0:0:Other:/var/empty:/sbin/nologin\n",
		master + "other:*:789:0456::0:0:Other:/var/empty:/sbin/nologin\n",
		master + "other:malformed\n",
	} {
		if _, e := accountIdentity(bad, group); e == nil {
			t.Fatal("unsafe account readback accepted")
		}
	}
	for _, bad := range []string{
		"wheel:*:0:root\n", group + "other:*:456:\n", group + "other:*:789:_aegvium\n",
		group + "_aegvium:*:456:\n", strings.Replace(group, "456:", "456:other", 1),
		group + "other:*:0456:\n",
		strings.Repeat("x", 262145),
	} {
		if _, e := accountIdentity(master, bad); e == nil {
			t.Fatal("unsafe group readback accepted")
		}
	}
}
