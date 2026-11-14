"""
Frontier-targeted mutant selection.

A conditional jump is on the coverage frontier of the current corpus if the corpus reaches
it but only ever goes one way: the other side is code the fuzzer has not been able to get
into through this check. Mutating such a jump to force the missing side is the mutant most
likely to let the fuzzer explore something new (cf. T-Fuzz's "non-critical checks").

Which sides are taken is found with the same HALT trick as the reachability check, run
with the same command (--reachability_check_cmd, which must exit non-zero if the corpus
crashes the executable), always on the real binary:

  * "not taken" probe: HALT on the instruction after the jump (the fall-through), jump
    unchanged: the corpus crashes iff the jump is executed without being taken;
  * "taken" probe: the jump's condition inverted and HALT on the fall-through: the corpus
    crashes iff the jump is executed with its condition true, i.e. taken.

(Both probes also fire if the fall-through address is reached some other way, e.g. as a
jump target; that can only make a jump look like it goes both ways, so it errs towards
not calling a jump a frontier.) A jump that is never taken is only a frontier if its
target is not reached some other way either, which a third probe (HALT on the target)
checks: forcing a jump into code the corpus already covers explores nothing new.

Results are cached: once both sides have been seen they stay seen. Jumps not reached at
all, and frontier jumps, are re-probed later because the corpus keeps growing. The search
uses group testing (see find), since most jumps of a large program are not reached.
"""
import os
import random
import re
import subprocess

from muttfuzz import mutate


class FrontierFinder:  # pylint: disable=too-many-instance-attributes
    """Finds and caches frontier jumps by HALT-probing the executable with a corpus-replay command."""

    def __init__(self, code, jumps, function_reach, executable, work_dir, run_check, recheck_after=10,
                 unreach_cache=None, group_size=512):
        """run_check() runs the reachability command on the executable and returns its
        return code (non-zero means the HALT was hit)."""
        self.code = code
        self.jumps = jumps
        self.function_reach = function_reach
        self.executable = executable
        self.probe_file = os.path.join(work_dir, "frontier_probe")
        self.run_check = run_check
        self.recheck_after = recheck_after
        self.unreach_cache = unreach_cache if unreach_cache is not None else {}
        self.status = {}          # loc -> (status, mutant_no checked)
        self.times_used = {}      # loc -> number of mutants made from it
        self.probes_run = 0
        self.group_size = group_size
        self.pending = []         # groups of jumps still to be explored (kept across mutants)

    def _probe(self, probe_code):
        with open(self.probe_file, "wb") as f:
            f.write(probe_code)
        os.rename(self.probe_file, self.executable)
        subprocess.check_call(["chmod", "+x", self.executable])
        self.probes_run += 1
        try:
            return self.run_check() != 0
        finally:
            with open(self.probe_file, "wb") as f:
                f.write(self.code)
            os.rename(self.probe_file, self.executable)

    def classify(self, loc, mutant_no):
        """Probe a jump: 'both', 'none' (not reached), 'taken' (only ever taken: the
        not-taken side is the frontier), 'not_taken' (never taken, and its target is not
        reached otherwise) or 'target_covered' (never taken, but its target is reached by
        some other path, so not a frontier)."""
        hexdata = self.jumps[loc]["hexdata"]
        fall_through = loc + len(hexdata)
        not_taken_probe = bytearray(self.code)
        not_taken_probe[fall_through] = mutate.HALT_OP
        seen_not_taken = self._probe(not_taken_probe)
        taken_probe = bytearray(self.code)
        flipped = mutate.NEAR_FLIP[hexdata[1]] if hexdata[0] == 15 else mutate.SHORT_FLIP[hexdata[0]]
        taken_probe[loc:loc + len(flipped)] = flipped
        taken_probe[fall_through] = mutate.HALT_OP
        seen_taken = self._probe(taken_probe)
        if seen_taken and seen_not_taken:
            status = "both"
        elif seen_taken:
            status = "taken"
        elif seen_not_taken:
            status = "not_taken"
            target = self.target_offset(loc)
            if target is not None and 0 <= target < len(self.code):
                target_probe = bytearray(self.code)
                target_probe[target] = mutate.HALT_OP
                if self._probe(target_probe):
                    status = "target_covered"
        else:
            status = "none"
        self.status[loc] = (status, mutant_no)
        return status

    def target_offset(self, loc):
        """File offset of the jump's target, from objdump's line for it
        ("  1278:\t7e 17 \tjle    1291 <check+0x32>"), or None."""
        line = self.jumps[loc]["code"]
        m_addr = re.match(r"\s*([0-9a-f]+):", line)
        m_target = re.search(r"\tj[a-z]+\s+([0-9a-f]+)\b", line)
        if not (m_addr and m_target):
            return None
        return int(m_target.group(1), 16) + (loc - int(m_addr.group(1), 16))

    def _probe_reached(self, locs):
        """One corpus run with a HALT on every jump in locs: does the corpus reach any of them?"""
        probe = bytearray(self.code)
        for loc in locs:
            probe[loc] = mutate.HALT_OP
        return self._probe(probe)

    def _unsettled(self, loc, mutant_no):
        """Not yet probed, or last seen unreached long enough ago to be worth another look."""
        if loc in self.unreach_cache or self.jumps[loc]["function_name"] in self.unreach_cache:
            return False
        st = self.status.get(loc)
        return st is None or (st[0] == "none" and mutant_no - st[1] >= self.recheck_after)

    def _known_frontier(self):
        locs = [loc for loc, (st, _) in self.status.items() if st in ("taken", "not_taken")]
        random.shuffle(locs)
        return sorted(locs, key=lambda l: self.times_used.get(l, 0))

    def _use(self, loc, status):
        self.times_used[loc] = self.times_used.get(loc, 0) + 1
        return (loc, status)

    def find(self, mutant_no, max_probes):
        """Returns (loc, status) for a frontier jump, or None if none was found within
        max_probes corpus runs.

        1. Frontier jumps found earlier but not yet used are re-verified (the corpus may
           have reached the missing side meanwhile) and used.
        2. Otherwise unsettled jumps are explored by group testing: one corpus run with a
           HALT on every jump of a group (default 512) tells whether any of them is reached;
           an unreached group is settled in one run, a reached one is split in halves.
           Single reached jumps are classified (2-3 runs). Most jumps of a big program are
           not reached by a given corpus, so this is far cheaper than probing jumps one at a
           time. Unfinished groups carry over to the next mutant.
        3. If nothing new turns up, the least-used known frontier jump is reused."""
        start = self.probes_run

        def budget_left():
            return self.probes_run - start < max_probes

        for loc in [l for l in self._known_frontier() if self.times_used.get(l, 0) == 0]:
            if not budget_left():
                return None
            status = self.classify(loc, mutant_no)
            if status in ("taken", "not_taken"):
                return self._use(loc, status)

        while budget_left():
            if not self.pending:
                fresh = [loc for loc in self.jumps if self._unsettled(loc, mutant_no)]
                if not fresh:
                    break
                random.shuffle(fresh)
                for i in range(0, len(fresh), self.group_size):
                    self.pending.append(fresh[i:i + self.group_size])
                self.pending.reverse()
            group = [loc for loc in self.pending.pop() if self._unsettled(loc, mutant_no)]
            if not group:
                continue
            if len(group) == 1:
                status = self.classify(group[0], mutant_no)
                if status in ("taken", "not_taken"):
                    return self._use(group[0], status)
                continue
            if not self._probe_reached(group):
                for loc in group:
                    self.status[loc] = ("none", mutant_no)
                continue
            half = len(group) // 2
            self.pending.append(group[half:])
            self.pending.append(group[:half])

        for loc in self._known_frontier():
            if not budget_left():
                break
            status = self.classify(loc, mutant_no)
            if status in ("taken", "not_taken"):
                return self._use(loc, status)
        return None

    def mutant(self, loc, status):
        """The mutant that forces the side the corpus never takes: an unconditional jump
        if the jump is never taken, NOPs if it is always taken. Returns the new bytes."""
        hexdata = self.jumps[loc]["hexdata"]
        if status == "not_taken":
            return mutate.NEAR_JUMPS[-1] if hexdata[0] == 15 else mutate.SHORT_JUMPS[-1]
        return mutate.NOP * len(hexdata)
