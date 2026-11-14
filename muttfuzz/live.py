"""
Live mutant switching: apply a mutant to the processes of a running fuzzer instead of
restarting the fuzzer on a mutated copy of the executable.

muttfuzz mutants only change a few bytes of already-instrumented code, so the coverage map
of a mutant is laid out exactly like the original's. A fuzzer that keeps running across
mutants therefore keeps its queue, scheduling state and coverage map; only the code
changes underneath it.

The bytes are written through /proc/<pid>/mem, which (like a debugger setting a
breakpoint) works on read-only code pages and only changes the target process's private
copy of the page, never the file on disk. They are written into every process of the
fuzzer's process tree that is running the executable:
  * AFL-style fork servers: the fork-server process, so every child forked from then on
    runs the mutant, plus any live (e.g. persistent-mode) children;
  * in-process fuzzers (libFuzzer etc.): the fuzzer process itself.
Writing to another process's memory needs ptrace-level access. muttfuzz is an ancestor of
the fuzzer processes, which Linux's default Yama setting (ptrace_scope=1) allows; in
Docker, --cap-add=SYS_PTRACE may still be needed.

x86 conditional-jump mutations change one or two bytes (the opcode), so writes to a
running in-process fuzzer are atomic in practice.
"""
import os
import time


def _ppid_map():
    children = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % pid) as f:
                stat = f.read()
        except OSError:
            continue
        # comm may contain spaces/parens; ppid is the 2nd field after the last ")"
        try:
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
        except (IndexError, ValueError):
            continue
        children.setdefault(ppid, []).append(int(pid))
    return children


def _descendants(root):
    children = _ppid_map()
    result, todo = [], [root]
    while todo:
        p = todo.pop()
        for c in children.get(p, []):
            result.append(c)
            todo.append(c)
    return result


def _strip_deleted(path):
    return path[:-len(" (deleted)")] if path.endswith(" (deleted)") else path


class LivePatcher:
    """Writes byte patches (file offset -> bytes) into the running processes of the
    executable that are descendants of root_pid."""

    def __init__(self, executable, root_pid, verbose=False):
        self.executable = os.path.realpath(executable)
        self.root_pid = root_pid
        self.verbose = verbose

    def processes(self):
        procs = []
        for pid in [self.root_pid] + _descendants(self.root_pid):
            try:
                exe = _strip_deleted(os.readlink("/proc/%d/exe" % pid))
            except OSError:
                continue
            if exe == self.executable:
                procs.append(pid)
        return procs

    def _mappings(self, pid):
        maps = []
        with open("/proc/%d/maps" % pid) as f:
            for line in f:
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                if _strip_deleted(parts[5].strip()) != self.executable:
                    continue
                start, end = (int(x, 16) for x in parts[0].split("-"))
                maps.append((start, end, int(parts[2], 16)))
        return maps

    def _address(self, maps, offset):
        for start, end, file_off in maps:
            if file_off <= offset < file_off + (end - start):
                return start + (offset - file_off)
        return None

    def _patch_pid(self, pid, patches):
        """Returns True if every patch is in place in pid afterwards."""
        try:
            maps = self._mappings(pid)
            with open("/proc/%d/mem" % pid, "r+b", buffering=0) as mem:
                for offset, data in patches:
                    addr = self._address(maps, offset)
                    if addr is None:
                        return False
                    mem.seek(addr)
                    if mem.read(len(data)) != data:
                        mem.seek(addr)
                        mem.write(data)
                    mem.seek(addr)
                    if mem.read(len(data)) != data:
                        return False
            return True
        except (OSError, ValueError):
            # process exited (fork-server children come and go): nothing to patch
            return not os.path.exists("/proc/%d" % pid)

    def apply(self, patches, passes=3):
        """patches: list of (file_offset, bytes). Repeats until a pass finds every process
        already patched, so children forked from an unpatched parent mid-way are caught.
        Returns the number of processes patched (0 means the fuzzer is not running the
        executable, e.g. it has not started or has died)."""
        patched = set()
        for _ in range(passes):
            procs = self.processes()
            if not procs:
                break
            all_ok = True
            for pid in procs:
                if self._patch_pid(pid, patches):
                    patched.add(pid)
                else:
                    all_ok = False
            if all_ok:
                break
            time.sleep(0.05)
        if self.verbose:
            print("LIVE-PATCHED", len(patches), "LOCATIONS IN", len(patched), "PROCESSES")
        return len(patched)


def diff(original, mutant, chunk=1 << 16):
    """Byte differences between two executable images, as contiguous runs.
    Compares 64 KiB chunks first, so only the few chunks a mutant touches are scanned."""
    patches = []
    n = min(len(original), len(mutant))
    mo, mm = memoryview(original), memoryview(mutant)
    for base in range(0, n, chunk):
        top = min(base + chunk, n)
        if mo[base:top] == mm[base:top]:
            continue
        i = base
        while i < top:
            if original[i] != mutant[i]:
                j = i
                while j < n and original[j] != mutant[j]:
                    j += 1
                if patches and patches[-1][0] + len(patches[-1][1]) == i:
                    off, data = patches.pop()
                    patches.append((off, data + bytes(mutant[i:j])))
                else:
                    patches.append((i, bytes(mutant[i:j])))
                i = j
            else:
                i += 1
    return patches


def inverse(original, patches):
    """The patches that restore the original bytes."""
    return [(off, bytes(original[off:off + len(data)])) for off, data in patches]
