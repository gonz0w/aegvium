# SPDX-License-Identifier: BSD-3-Clause
"""Closed-entry Aeg-only first-image source coordinator, not an image importer.

Nothing runs at import. Candidate construction is private and has no CLI override.
The incomplete operational integration and unqualified native/input profile keep the
installed entry closed. A hash, archive or serialized receipt cannot create Owner.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
QEMU = Path('/opt/homebrew/Cellar/qemu/11.1.1/bin/qemu-system-x86_64')
BIOS = QEMU.parent.parent / 'share/qemu/bios-256k.bin'
QEMU_PIN = '25afcb2986e4a0f2c567de17273f55de3c99792b78a07c99e923bb62024c088f'
BIOS_PIN = 'ae6f6aa973aaccc143f57aa960fb035fd9de4daee4ad0cd713322f8c259e7650'
GO_PIN = '516c1fbb53b5f8f4852f0c3c379d45bcff53a1032e5cd1a9ca1738f03ba07cb1'
DISK_BYTES = 8 * 1024**3  # Fixed candidate fixture, not product capacity admission.
_ACTIVE = []  # Retain every uncertain process/FD owner; no reset or disposal path.
SUPERVISOR_INPUTS = (
    'cmd/aegvium-supervisor/main.c',
    *(f'internal/inspectorowner/{name}' for name in (
        'controller.c', 'controller.h', 'control_frame.c', 'control_frame.h',
        'launch_storage.c', 'launch_storage.h', 'storage_openbsd.c', 'storage_os.h',
        'native_construction.c', 'native_construction.h', 'native_openbsd.c',
        'native_os.h', 'launch_source.inc', 'launch_source_openbsd.c', 'launch_source_os.h',
        'diagnostics_source.inc')),
)


class Incomplete(Exception):
    pass


def _digest(fd):
    initial = os.fstat(fd)
    if initial.st_size < 1 or initial.st_size > 1024**3:
        raise Incomplete('candidate input size')
    h = hashlib.sha256()
    offset = 0
    while offset < initial.st_size:
        size = min(1024 * 1024, initial.st_size - offset)
        data = os.pread(fd, size, offset)
        if len(data) != size:
            raise Incomplete('candidate input truncated')
        h.update(data)
        offset += len(data)
    final = os.fstat(fd)
    if os.pread(fd, 1, offset) or (final.st_dev, final.st_ino, final.st_size) != (
            initial.st_dev, initial.st_ino, initial.st_size):
        raise Incomplete('candidate input changed')
    return h.hexdigest()


class _Owner:
    def __init__(self):
        raise Incomplete('no supplied image/input owner')

    @classmethod
    def _create(cls):
        self = object.__new__(cls)
        self.fds, self.child, self.tools, self.close_tried = [], None, [], set()
        self.failed, self.prepared = False, False
        _ACTIVE.append(self)
        # Actual fresh creation is the origin of target ownership, never a path
        # absence observation or imported metadata. The parent is private too.
        try:
            parent = ROOT / '.tools'
            for p in (parent, *parent.parents):
                s = p.stat(follow_symlinks=False)
                if (not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0, os.getuid()) or
                        s.st_mode & 0o022):
                    raise Incomplete('private ancestor')
            self.work = Path(tempfile.mkdtemp(prefix='commission-', dir=parent))
            self.dirfd = self._keep(os.open(self.work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
            s = os.fstat(self.dirfd)
            if s.st_uid != os.getuid() or s.st_mode & 0o7777 != 0o700:
                raise Incomplete('private creation')
            self._candidate()
            self._target_and_vm()
            return self  # Candidate ownership only, never production admission.
        except BaseException:
            self.failed = True
            self._stop_owned()
            raise

    def _keep(self, fd):
        self.fds.append(fd)
        return fd

    def _input(self, path):
        fd = self._keep(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK))
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
            raise Incomplete('candidate input shape')
        return fd

    def _close(self, fd):
        if fd in self.close_tried:
            raise Incomplete('close already attempted')
        self.close_tried.add(fd)
        os.close(fd)
        self.fds.remove(fd)

    def _new(self, name, mode=0o600):
        return self._keep(os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                                  os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=self.dirfd))

    def _write(self, name, data, mode=0o600):
        fd = self._new(name, mode)
        if os.write(fd, data) != len(data):
            raise Incomplete('short private write')
        os.fsync(fd)
        return fd

    def _command(self, args, *, cwd=None, env=None, output=None, seconds=120,
                 combined=False):
        # Only fixed source-defined commands call this private helper. No shell,
        # operator command, archive member, callback or provider selects argv.
        child = subprocess.Popen(args, cwd=cwd or self.work, env=env,
                                 stdin=subprocess.DEVNULL,
                                 stdout=output if output is not None else subprocess.DEVNULL,
                                 stderr=subprocess.STDOUT if combined else subprocess.DEVNULL,
                                 close_fds=True)
        self.tools.append(child)
        if child.wait(timeout=seconds) != 0:
            raise Incomplete('fixed candidate command failed')

    def _capture(self, name, args):
        fd = self._new(name)
        self._command(args, cwd=ROOT, output=fd)
        data = os.pread(fd, 4097, 0)
        if len(data) > 4096:
            raise Incomplete('fixed metadata bound')
        return data.strip()

    def _copy(self, source, name, pin, mode=0o400):
        fd = self._input(source)
        initial = os.fstat(fd)
        if initial.st_size < 1 or initial.st_size > 1024**3:
            raise Incomplete('private input bound')
        output = self._new(name)
        offset, h = 0, hashlib.sha256()
        while offset < initial.st_size:
            size = min(1024 * 1024, initial.st_size - offset)
            data = os.pread(fd, size, offset)
            if len(data) != size:
                raise Incomplete('private input truncated')
            if os.write(output, data) != len(data):
                raise Incomplete('short private input copy')
            h.update(data); offset += len(data)
        if h.hexdigest() != pin:
            raise Incomplete('private input identity')
        final = os.fstat(fd)
        if os.pread(fd, 1, offset) or (final.st_dev, final.st_ino, final.st_size) != (
                initial.st_dev, initial.st_ino, initial.st_size):
            raise Incomplete('private input changed')
        os.fchmod(output, mode); os.fsync(output)
        if _digest(output) != pin:
            raise Incomplete('private input readback')
        return output

    def _candidate(self):
        # Existing trusted SSH signing configuration authenticates source review;
        # it does not authorize commissioning, signing, distribution or execution.
        commit = self._capture('candidate.commit', ['/usr/bin/git', 'rev-parse', 'HEAD'])
        if len(commit) != 40 or any(c not in b'0123456789abcdef' for c in commit):
            raise Incomplete('source commit shape')
        self.commit = commit.decode('ascii')
        common = Path(os.fsdecode(self._capture('git.common', [
            '/usr/bin/git', 'rev-parse', '--path-format=absolute', '--git-common-dir'])))
        primary = common.parent
        signers = primary / '.tools/allowed_signers'
        signer_fd = self._input(signers)
        self._copy(signers, 'allowed_signers', _digest(signer_fd))
        self._command(['/usr/bin/git', '-c',
                       'gpg.ssh.allowedSignersFile=' + str(self.work / 'allowed_signers'),
                       'verify-commit', self.commit], cwd=ROOT)
        exported = self._new('source.tar')
        self._command(['/usr/bin/git', 'archive', '--format=tar', self.commit, 'go.mod', 'go.sum',
                       'cmd', 'internal', 'tools/native/aegvium-install.site',
                       'research/native/official-release-pins.json'],
                      cwd=ROOT, output=exported)
        os.fsync(exported)
        if os.fstat(exported).st_size > 64 * 1024**2:
            raise Incomplete('source bound')
        source = self.work / 'source'
        source.mkdir(mode=0o700)
        with os.fdopen(os.dup(exported), 'rb') as stream:
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode='r:') as archive:
                members = archive.getmembers()
                if len(members) > 4096 or sum(m.size for m in members) > 64 * 1024**2:
                    raise Incomplete('source export bound')
                if any(not (m.isdir() or m.isreg()) or m.name.startswith('/') or
                       '..' in Path(m.name).parts for m in members):
                    raise Incomplete('source export shape')
                archive.extractall(source, members=members, filter='data')
        # Build the actual source entry, never the default refusal stub. Missing
        # graph/input/role prerequisites must refuse before creating a target.
        compiler = primary / '.tools/go/bin/go'
        gofd = self._input(compiler)
        if _digest(gofd) != GO_PIN:
            raise Incomplete('compiler input identity')
        self._copy(compiler, 'go', GO_PIN, 0o500)
        compiler = self.work / 'go'
        env = dict(PATH='/usr/bin:/bin', GOENV='off', GOFLAGS='', GOTOOLCHAIN='local',
                   GOPROXY=(Path.home() / 'go/pkg/mod/cache/download').as_uri(), GOSUMDB='off',
                   GOMODCACHE=str(self.work / 'go-mod'),
                   CGO_ENABLED='0', GOMAXPROCS='2', GOCACHE=str(self.work / 'go-cache'),
                   GOROOT=str(primary / '.tools/go'), GOOS='openbsd', GOARCH='amd64')
        for package, name, tags in (
            ('./cmd/aegvium-inspector', 'inspector', 'aegvium_transport_source,aegvium_engine_source,no_fs_access'),
            ('./cmd/aegvium-place', 'place', 'aegvium_commission_source'),
        ):
            self._command([str(compiler), 'build', '-mod=readonly', '-p=2', '-trimpath',
                           '-tags=' + tags, '-o', str(self.work / name), package],
                          cwd=source, env=env, seconds=600)
        image = self._input(self.work / 'inspector')
        image_pin = _digest(image)
        pair = self._input(ROOT / '.tools/commission-inputs/pair.snapshot')
        pair_data = os.pread(pair, 8193, 0)
        if (len(pair_data) > 8192 or len(pair_data) < 47 or
                (pair_data[:8], pair_data[40:47]) not in
                ((b'AGPAIR1\n', b'M2-H1/1'), (b'AGPAIR2\n', b'M2-H1/3'))):
            raise Incomplete('paired input bound')
        self.pair = bytes(pair_data)
        self.generation = self.pair[8:40]
        self.pair_pin = hashlib.sha256(self.pair).hexdigest().encode()
        self._write('pair.snapshot', self.pair)
        env.update(GOOS='darwin', GOARCH='arm64')
        self._command([str(compiler), 'build', '-mod=readonly', '-p=2', '-trimpath',
                       '-o', str(self.work / 'payload-builder'), './cmd/aegvium-payload'],
                      cwd=source, env=env, seconds=600)
        self._command([str(self.work / 'payload-builder'), '-pair', str(self.work / 'pair.snapshot'),
                       '-inspector', str(self.work / 'inspector'), '-sha256', image_pin,
                       '-output', str(self.work / 'payload.tar')], seconds=120)
        self.payload = self._input(self.work / 'payload.tar')
        self.payload_pin = _digest(self.payload).encode()
        self._role_inputs()
        self._frontend_inputs()
        # Reuse only read-only stock release verification, not baseline/SSH or
        # its booted-image admission. This path has no download fallback.
        pins = json.loads((source / 'research/native/official-release-pins.json').read_text())
        stock_input = ROOT / '.tools/commission-inputs/official'
        stock = self.work / 'official'
        stock.mkdir(mode=0o700)
        for name, pin in pins['assets'].items():
            self._copy(stock_input / name, 'official/' + name, pin['sha256'])
        self._copy(stock_input / 'signify', 'official/signify',
                   pins['verifier']['executable_sha256'], 0o500)
        verification = self._new('official-verification')
        self._command([str(stock / 'signify'), '-C', '-p', 'openbsd-79-base.pub',
                       '-x', 'SHA256.sig', 'install79.iso'], cwd=stock,
                      output=verification, seconds=60, combined=True)
        if os.pread(verification, 4097, 0).splitlines() != [b'Signature Verified', b'install79.iso: OK']:
            raise Incomplete('official authentication incomplete')
        for name, pin in pins['assets'].items():
            fd = self._input(stock / name)
            if _digest(fd) != pin['sha256']:
                raise Incomplete('official input changed during verification')
        self.stock = self._input(stock / 'install79.iso')
        if _digest(self.stock) != pins['assets']['install79.iso']['sha256']:
            raise Incomplete('stock source changed')
        self._derived_media(source, stock)

    def _role_inputs(self):
        # This source path is never called by pure tests. Real provisioning is
        # held. Material remains private throughout derived media and retention.
        directory = ROOT / '.tools/commission-inputs/inspector'
        for path in (directory, directory.parent):
            s = path.stat(follow_symlinks=False)
            if (not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0, os.getuid()) or
                    s.st_mode & 0o022):
                raise Incomplete('protected role directory')
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > 23:
                    raise Incomplete('role input count')
        names.sort()
        fixed = {'cert.pem', 'key.pem', 'server.der', 'backend.conf',
                 'backend-cert.pem', 'backend-key.pem', 'backend-client-root.der'}
        if len(names) < 9 or len(names) > 23 or not fixed <= set(names):
            raise Incomplete('role input set')
        (self.work / 'roles').mkdir(mode=0o700)
        self.roles = []
        for name in names:
            limit = 8192 if name == 'backend.conf' else 65536 if name in ('cert.pem', 'backend-cert.pem') else 16384
            if name not in fixed:
                prefix = 'backend-' if name.startswith('backend-') else 'client-'
                pin = name[len(prefix):-4]
                if (not name.startswith(prefix) or not name.endswith('.der') or
                        len(pin) != 64 or any(c not in '0123456789abcdef' for c in pin)):
                    raise Incomplete('role input name')
            incoming = self._input(directory / name)
            s = os.fstat(incoming)
            if (s.st_uid not in (0, os.getuid()) or s.st_mode & 0o7777 not in (0o400, 0o600) or
                    s.st_size < 1 or s.st_size > limit):
                raise Incomplete('protected role input')
            output = self._copy(directory / name, 'roles/' + name, _digest(incoming))
            if os.fstat(output).st_size != s.st_size:
                raise Incomplete('role input changed')
            self.roles.append((name, output, s.st_size))

    def _frontend_inputs(self):
        # Explicit composition: requested standalone protection cannot silently
        # fall back to the externally supplied frontend profile. No key is parsed.
        parent = ROOT / '.tools/commission-inputs'
        mode = self._input(parent / 'frontend-mode')
        st = os.fstat(mode)
        if (st.st_uid not in (0, os.getuid()) or st.st_mode & 0o7777 not in (0o400, 0o600) or
                st.st_size < 1 or st.st_size > 9):
            raise Incomplete('frontend composition input')
        raw = os.pread(mode, 10, 0)
        if raw not in (b'external\n', b'bundled\n'):
            raise Incomplete('frontend composition mode')
        self._copy(parent / 'frontend-mode', 'frontend-mode', _digest(mode))
        self.frontend = []
        directory = parent / 'frontend'
        if raw == b'external\n':
            try:
                directory.lstat()
            except FileNotFoundError:
                return
            raise Incomplete('unexpected bundled frontend inputs')
        if self.pair[:8] != b'AGPAIR2\n' or self.pair[40:47] != b'M2-H1/3':
            raise Incomplete('bundled frontend requires DATA descriptor')
        for path in (directory, parent):
            st = path.stat(follow_symlinks=False)
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.getuid()) or st.st_mode & 0o022):
                raise Incomplete('protected frontend input directory')
        limits = {'frontend-role': 253, 'frontend-listen': 21, 'public.pem': 81920,
                  'frontend.pem': 81920, 'inspector-root.pem': 32768,
                  'server.der': 16384, 'client.der': 16384}
        with os.scandir(directory) as entries:
            names = [entry.name for _, entry in zip(range(8), entries)]
        if len(names) != len(limits) or set(names) != set(limits):
            raise Incomplete('frontend input set')
        (self.work / 'frontend').mkdir(mode=0o700)
        for name in sorted(limits):
            incoming = self._input(directory / name)
            st = os.fstat(incoming)
            if (st.st_uid not in (0, os.getuid()) or st.st_mode & 0o7777 not in (0o400, 0o600) or
                    st.st_size < 1 or st.st_size > limits[name]):
                raise Incomplete('bounded frontend input')
            output = self._copy(directory / name, 'frontend/' + name, _digest(incoming))
            if os.fstat(output).st_size != st.st_size:
                raise Incomplete('frontend input changed')
            self.frontend.append((name, output, st.st_size))

    def _derived_media(self, source, stock):
        tree = self.work / 'media'
        tree.mkdir(mode=0o700)
        self._command(['/usr/bin/tar', '-xf', str(stock / 'install79.iso'), '-C', str(tree)], seconds=120)
        expected = self.payload_pin + b'\n' + self.generation + b'\n' + self.pair_pin + b'\n'
        site = tree / '7.9/amd64/site79.tgz'
        with site.open('xb') as output:
            with tarfile.open(fileobj=output, mode='w:gz') as archive:
                data = (source / 'tools/native/aegvium-install.site').read_bytes()
                for name, mode, blob in (
                    ('install.site', 0o500, data),
                    ('aegvium.install', 0o700, None),
                    ('aegvium.install/place', 0o500, (self.work / 'place').read_bytes()),
                    ('aegvium.install/expected', 0o400, expected),
                    ('aegvium.install/supervisor-source', 0o700, None),
                    ('aegvium.install/roles', 0o700, None),
                    ('aegvium.install/frontend-mode', 0o400, (self.work / 'frontend-mode').read_bytes()),
                ):
                    h = tarfile.TarInfo(name); h.uid = h.gid = 0; h.mode = mode
                    h.type = tarfile.DIRTYPE if blob is None else tarfile.REGTYPE
                    h.size = 0 if blob is None else len(blob)
                    archive.addfile(h, None if blob is None else io.BytesIO(blob))
                if self.frontend:
                    h = tarfile.TarInfo('aegvium.install/frontend')
                    h.uid = h.gid = 0; h.mode = 0o700; h.type = tarfile.DIRTYPE
                    archive.addfile(h)
                    for name, fd, size in self.frontend:
                        h = tarfile.TarInfo('aegvium.install/frontend/' + name)
                        h.uid = h.gid = 0; h.mode = 0o400; h.size = size
                        with os.fdopen(os.dup(fd), 'rb') as incoming:
                            incoming.seek(0); archive.addfile(h, incoming)
                total_source = 0
                for name in SUPERVISOR_INPUTS:
                    blob = (source / name).read_bytes()
                    total_source += len(blob)
                    if not blob or len(blob) > 65536 or total_source > 262144:
                        raise Incomplete('fixed supervisor source bound')
                    h = tarfile.TarInfo('aegvium.install/supervisor-source/' + Path(name).name)
                    h.uid = h.gid = 0; h.mode = 0o400; h.size = len(blob)
                    archive.addfile(h, io.BytesIO(blob))
                for name, fd, size in self.roles:
                    h = tarfile.TarInfo('aegvium.install/roles/' + name)
                    h.uid = h.gid = 0; h.mode = 0o400; h.size = size
                    with os.fdopen(os.dup(fd), 'rb') as incoming:
                        incoming.seek(0); archive.addfile(h, incoming)
                h = tarfile.TarInfo('aegvium.install/payload.tar')
                h.uid = h.gid = 0; h.mode = 0o400; h.size = os.fstat(self.payload).st_size
                with os.fdopen(os.dup(self.payload), 'rb') as incoming:
                    incoming.seek(0); archive.addfile(h, incoming)
            output.flush(); os.fsync(output.fileno())
        # No password is generated: retained stock password handling recognizes
        # this exact disabled marker (install.sub2915..2917). No SSH/NIC/user.
        answers = b'''System hostname = aegvium
Which network interface = done
Password for root account = *************
Start sshd = no
Do you expect to run the X Window System = no
Setup a user = no
What timezone = UTC
Which disk is the root disk = sd0
Use (W)hole disk MBR, whole disk (G)PT or (E)dit = whole
Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = a
Location of sets = cd0
Pathname to the sets = 7.9/amd64
Set name(s) = bsd bsd.mp bsd.rd base79.tgz comp79.tgz man79.tgz site79.tgz
Directory does not contain SHA256.sig. Continue without verification = yes
Location of sets = done
'''
        with (tree / 'aegvium.conf').open('xb') as output:
            output.write(answers); output.flush(); os.fsync(output.fileno())
        self._command(['/usr/bin/hdiutil', 'makehybrid', '-iso', '-joliet', '-no-emul-boot',
                       '-boot-load-size', '4', '-eltorito-boot', '7.9/amd64/cdbr',
                       '-o', str(self.work / 'installer.iso'), str(tree)], seconds=120)
        self.media = self._input(self.work / 'installer.iso')
        os.fsync(self.media)

    def _until(self, needle, deadline, pending):
        while needle not in pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or len(pending) > 8 * 1024**2:
                raise Incomplete('installer observation bound')
            ready, _, _ = select.select([self.child.stdout], [], [], min(remaining, 1))
            if not ready:
                continue
            data = os.read(self.child.stdout.fileno(), 4096)
            if not data:
                raise Incomplete('installer observation incomplete')
            pending = (pending + data).replace(b'\r\n', b'\n')
        return pending

    def _target_and_vm(self):
        # The sole raw target is born here, after actual local input construction.
        self.disk = self._new('target.raw')
        os.ftruncate(self.disk, DISK_BYTES); os.fsync(self.disk); os.fsync(self.dirfd)
        self.target_stat = os.fstat(self.disk)
        q = self._input(QEMU); bios = self._input(BIOS)
        if _digest(q) != QEMU_PIN or _digest(bios) != BIOS_PIN:
            raise Incomplete('fixed VM inputs changed')
        self._copy(QEMU, 'qemu', QEMU_PIN, 0o500)
        self._copy(BIOS, 'bios.bin', BIOS_PIN)
        deadline = time.monotonic() + 3600
        args = [str(self.work / 'qemu'), '-L', str(BIOS.parent),
                '-machine', 'pc-i440fx-11.1,accel=tcg,hpet=off,smm=off',
                '-bios', str(self.work / 'bios.bin'), '-cpu', 'max', '-smp', '2', '-m', '2048',
                '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-nic', 'none',
                '-no-reboot', '-boot', 'order=d,strict=on',
                '-add-fd', 'fd=' + str(self.disk) + ',set=1',
                '-add-fd', 'fd=' + str(self.media) + ',set=2',
                '-drive', 'file=/dev/fdset/1,format=raw,if=virtio',
                '-drive', 'file=/dev/fdset/2,format=raw,media=cdrom,readonly=on']
        self.child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, close_fds=True,
                                      pass_fds=(self.disk, self.media))
        pending = self._until(b'boot> ', deadline, b'')
        self.child.stdin.write(b'set tty com0\nboot\n'); self.child.stdin.flush()
        pending = self._until(b'(S)hell?', deadline, pending)
        self.child.stdin.write(b's\nmount -t cd9660 /dev/cd0a /mnt2\n/install -af /mnt2/aegvium.conf\n')
        self.child.stdin.flush()
        marker = b'AGPLACED1 ' + self.generation + b' ' + self.pair_pin + b' ' + self.payload_pin + b'\n'
        pending = self._until(marker, deadline, pending)
        if pending.count(marker) != 1:
            raise Incomplete('ambiguous placement observation')
        supervisor = [line[14:] for line in pending.splitlines() if line.startswith(b'AGSUPERVISOR1 ')]
        if (len(supervisor) != 1 or len(supervisor[0]) != 64 or
                any(c not in b'0123456789abcdef' for c in supervisor[0])):
            raise Incomplete('supervisor placement observation')
        self.supervisor_pin = supervisor[0]  # Observed compiler output, not release admission.
        self.child.stdin.close()
        # QEMU exits on the stock installer's reboot request. No target boot,
        # restart, snapshot, QMP reset or import is submitted by this owner.
        while True:
            if time.monotonic() >= deadline:
                raise Incomplete('owned VM deadline')
            ready, _, _ = select.select([self.child.stdout], [], [], 0.2)
            if ready:
                tail = os.read(self.child.stdout.fileno(), 4096)
                if not tail:
                    break
                pending = (pending + tail).replace(b'\r\n', b'\n')
                if (len(pending) > 8 * 1024**2 or pending.count(marker) != 1 or
                        pending.count(b'AGSUPERVISOR1 ') != 1):
                    raise Incomplete('duplicate placement observation')
        if self.child.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise Incomplete('owned VM termination failed')
        self.child.stdout.close()
        os.fsync(self.disk)
        now = os.fstat(self.disk)
        if (now.st_dev, now.st_ino, now.st_nlink, now.st_size) != (
                self.target_stat.st_dev, self.target_stat.st_ino, 1, DISK_BYTES):
            raise Incomplete('target lifetime identity')
        # Keep the actual target descriptor and paired snapshot as unadmitted
        # candidate data. Actual frontend-owner handoff has not been implemented.
        for fd in list(self.fds):
            if fd not in (self.disk, self.dirfd):
                self._close(fd)
        os.fsync(self.dirfd)
        self.prepared = True

    def _stop_owned(self):
        # Only actual Popen children, never a supplied PID or historical group.
        for child in reversed(self.tools + ([self.child] if self.child is not None else [])):
            if child.poll() is not None:
                child.wait()
                continue
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


if __name__ == '__main__':
    raise SystemExit('commissioning entry closed: role placement/frontend handoff/native qualification incomplete')
