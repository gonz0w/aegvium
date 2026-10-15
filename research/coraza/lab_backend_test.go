// SPDX-License-Identifier: BSD-3-Clause
package spike

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

const backendProbeBody = `{"payload":"<script>alert(1)</script>"}`
const backendSyncRoot = "/var/aegvium-lab-backend-sync"

type backendProbeEffect struct{ authority, body string }
type backendProbeRow struct {
	Phase       string `json:"phase"`
	Case        string `json:"case"`
	InputSHA    string `json:"input_sha256"`
	CAHash      string `json:"ca_sha256"`
	Connected   bool   `json:"connected"`
	VerifiedTLS bool   `json:"verified_tls"`
	Status      int    `json:"status"`
	Error       string `json:"error"`
}
type backendEffectRow struct {
	Phase     string `json:"phase"`
	Case      string `json:"case"`
	Backend   int    `json:"backend"`
	Authority string `json:"authority"`
	BodySHA   string `json:"body_sha256"`
}

func backendPhase() (string, bool) {
	phase := os.Getenv("AEGVIUM_SENDER_PHASE")
	return phase, phase == "baseline" || phase == "protected" || phase == "rollback" || phase == "reprotected"
}
func backendGuard(t *testing.T, uid int) (string, string) {
	t.Helper()
	if runtime.GOOS != "openbsd" || os.Getenv("AEGVIUM_BACKEND_ISOLATION") != "owned-guest" {
		t.Skip("owned OpenBSD backend isolation required")
	}
	phase, valid := backendPhase()
	token := os.Getenv("AEGVIUM_BACKEND_TOKEN")
	if !valid || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(token) || os.Getuid() != uid || os.Geteuid() != uid {
		t.Fatal("backend principal/phase/run guard")
	}
	return phase, token
}

// Public synchronization only. A peer cannot supply commands, paths or policies.
func backendRead(path string, uid int, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0644 || before.Size() > limit {
		return nil, errors.New("backend public file invalid")
	}
	if runtime.GOOS == "openbsd" && int(before.Sys().(*syscall.Stat_t).Uid) != uid {
		return nil, errors.New("backend public owner invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("backend public file replaced")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("backend public file unavailable")
	}
	return data, nil
}
func backendPublish(path string, data []byte) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("backend public destination exists")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".publish-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Chmod(0644); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
func backendWait(path string, uid int, expected string) error {
	until := time.Now().Add(20 * time.Second)
	for {
		data, err := backendRead(path, uid, 256)
		if err == nil {
			if string(data) != expected {
				return errors.New("backend public marker mismatch")
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) || !time.Now().Before(until) {
			return errors.New("backend public marker unavailable")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func backendMarker(phase, token string) string { return phase + "\n" + token + "\n" }

func TestLabBackendIsolation(t *testing.T) {
	phase, _ := backendGuard(t, 32767)
	if os.Getenv("AEGVIUM_LAB_SENDER") != "owned-guest" {
		t.Fatal("backend sender guard")
	}
	runSenderPathOptions(t, phase, true, true, true)
}
func backendProbeFixture(t *testing.T, phase, certPath string, observe func() []backendProbeEffect) {
	t.Helper()
	actual, token := backendGuard(t, 32767)
	if actual != phase {
		t.Fatal("backend phase mismatch")
	}
	base := filepath.Join(backendSyncRoot, phase)
	public, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = backendPublish(filepath.Join(base, "fixture", "ca.pem"), public); err != nil {
		t.Fatal(err)
	}
	before := len(observe())
	if err = backendPublish(filepath.Join(base, "fixture", "ready"), []byte(backendMarker(phase, token))); err != nil {
		t.Fatal(err)
	}
	if err = backendWait(filepath.Join(base, "probe", "done"), 1, backendMarker(phase, token)); err != nil {
		t.Fatal(err)
	}
	after := observe()
	protected := phase == "protected" || phase == "reprotected"
	expected := 2
	if protected {
		expected = 0
	}
	if len(after)-before != expected {
		t.Fatal("foreign backend effect count", len(after)-before, expected)
	}
	for i, name := range []string{"plain", "api"} {
		row := backendEffectRow{Phase: phase, Case: name}
		if !protected {
			effect := after[before+i]
			host := "app.test"
			if name == "api" {
				host = "api.test"
			}
			if effect.authority != host || effect.body != backendProbeBody {
				t.Fatal("foreign backend bytes/authority drift")
			}
			hash := sha256.Sum256([]byte(effect.body))
			row.Backend, row.Authority, row.BodySHA = 1, effect.authority, hex.EncodeToString(hash[:])
		}
		data, _ := json.Marshal(row)
		t.Log("BACKEND-EFFECT " + string(data))
	}
	for _, name := range []string{"ready", "ca.pem"} {
		path := filepath.Join(base, "fixture", name)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("backend public asset remains")
		}
	}
	t.Logf("BACKEND-FIXTURE phase=%s public_assets_removed=true", phase)
}

func TestLabBackendProbe(t *testing.T) {
	phase, token := backendGuard(t, 1)
	base := filepath.Join(backendSyncRoot, phase)
	if err := backendWait(filepath.Join(base, "fixture", "ready"), 32767, backendMarker(phase, token)); err != nil {
		t.Fatal(err)
	}
	public, err := backendRead(filepath.Join(base, "fixture", "ca.pem"), 32767, 65536)
	if err != nil {
		t.Fatal(err)
	}
	caHash := sha256.Sum256(public)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(public) {
		t.Fatal("backend probe CA unavailable")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	_, err = io.Copy(digest, file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	binaryHash := digest.Sum(nil)
	t.Logf("BACKEND-PRINCIPAL phase=%s uid=%d euid=%d binary=%x ca_sha256=%x", phase, os.Getuid(), os.Geteuid(), binaryHash, caHash)
	for i, name := range []string{"plain", "api"} {
		t.Run(name, func(t *testing.T) {
			host := "app.test"
			if name == "api" {
				host = "api.test"
			}
			request := "POST / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: " + fmt.Sprint(len(backendProbeBody)) + "\r\n\r\n" + backendProbeBody
			inputHash := sha256.Sum256([]byte(name + "\x00" + request))
			row := backendProbeRow{Phase: phase, Case: name, InputSHA: hex.EncodeToString(inputHash[:]), CAHash: hex.EncodeToString(caHash[:])}
			protected := phase == "protected" || phase == "reprotected"
			connection, err := net.DialTimeout("tcp4", fmt.Sprint("127.0.0.1:", 18086+i), time.Second)
			row.Connected = err == nil
			if err != nil {
				var timeout net.Error
				if !protected || (errors.As(err, &timeout) && timeout.Timeout()) || (!errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, syscall.EHOSTUNREACH) && !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM)) {
					t.Fatal("unexpected foreign connect result", err)
				}
				row.Error = "denied"
			} else {
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(3 * time.Second))
				var wire net.Conn = connection
				if name == "api" {
					secure := tls.Client(connection, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12})
					if err = secure.Handshake(); err != nil {
						t.Fatal(err)
					}
					row.VerifiedTLS = len(secure.ConnectionState().VerifiedChains) > 0
					wire = secure
				}
				if _, err = io.WriteString(wire, request); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(wire), &http.Request{Method: "POST"})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
				response.Body.Close()
				if err != nil || string(body) != "owned sender backend\n" {
					t.Fatal("foreign response drift")
				}
				row.Status = response.StatusCode
			}
			raw, _ := json.Marshal(row)
			t.Log("BACKEND-PROBE " + string(raw))
			if protected {
				if row.Connected || row.Status != 0 || row.VerifiedTLS || row.Error != "denied" {
					t.Fatal("foreign backend bypassed")
				}
			} else if !row.Connected || row.Status != 200 || row.Error != "" || row.VerifiedTLS != (name == "api") {
				t.Fatal("foreign positive control unavailable")
			}
		})
	}
	if t.Failed() {
		return
	}
	if err := backendPublish(filepath.Join(base, "probe", "done"), []byte(backendMarker(phase, token))); err != nil {
		t.Fatal(err)
	}
}

func TestLabBackendPublicFiles(t *testing.T) {
	if runtime.GOOS == "openbsd" && (os.Getuid() != 32767 || os.Geteuid() != 32767) {
		t.Fatal("public test requires fixture UID")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "marker")
	token := strings.Repeat("a", 64)
	expected := backendMarker("baseline", token)
	if err := backendPublish(path, []byte(expected)); err != nil {
		t.Fatal(err)
	}
	if err := backendWait(path, os.Getuid(), expected); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "openbsd" {
		if _, err := backendRead(path, 1, 256); err == nil {
			t.Fatal("wrong public owner accepted")
		}
	}
	if err := backendPublish(path, []byte(expected)); err == nil {
		t.Fatal("existing marker replaced")
	}
	if err := backendWait(path, os.Getuid(), backendMarker("protected", token)); err == nil {
		t.Fatal("wrong phase accepted")
	}
	if err := backendWait(path, os.Getuid(), backendMarker("baseline", strings.Repeat("b", 64))); err == nil {
		t.Fatal("stale run accepted")
	}
	if _, err := backendRead(path, os.Getuid(), 1); err == nil {
		t.Fatal("unbounded public file")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := backendRead(link, os.Getuid(), 256); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := backendRead(path, os.Getuid(), 256); err == nil {
		t.Fatal("private file exposed")
	}
}
