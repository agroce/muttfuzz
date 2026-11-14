MuttFuzz doggedly fuzzes for you, mutating the executable as it goes!

<img src="muttfuzz.png" alt="drawing" width="200"/>

---------------------------------

**FAQ**

**Q**:  Is this a mutation testing tool?

**A**:  No.  MuttFuzz is only mutating your code in order to fuzz it better.  You don't need to care about the mutants, you'll never see them.  Coverage and bugs will be for your fuzzed program.  However, MuttFuzz does provide a mode in which it can give a quick-and-dirty mutation score estimate for a program.  See below.

**Q**: What fuzzing algorithm does MuttFuzz use?

**A**: MuttFuzz doesn't use a fuzzing algorithm.  MuttFuzz is a *meta-fuzzer*.  This means you tell MuttFuzz what fuzzer you're using (and how you call it), and where your executable is, and MuttFuzz will orchestrate a fuzzing campaign, doing some behind-the-scenes work on the fuzzed executable that is likely to improve the effectiveness of that fuzzing.  MuttFuzz should work with most popular fuzzing tools.

**Q**: What are major limitations of MuttFuzz?

**A**: Right now, MuttFuzz only works for x86 Linux, and MuttFuzz may not work well if 1) your fuzzer needs two executables (like Angora) or 2) your target program disassembles poorly using _objdump_.  That's it.  Also, of course, if you are fuzzing a library you'll need to statically link it into your executable.  Alternatively, just provide the dynamically linked library as the filename argument, since MuttFuzz doesn't assume the filename is a full executable.

**Q: How do I install MuttFuzz?**

**A**:

~~~
pip3 install muttfuzz
~~~

(perhaps with `--user`)

should do the trick.  Right now, there are no serious dependencies.

**Q: How do I use MuttFuzz?** 

**A**: Let's say you want to use AFL to fuzz a program whose compiled and AFL-instrumented executable is named `target` and which takes its input from `stdin`:

~~~
muttfuzz "afl-fuzz -i- -o fuzz_target -d ./target @@" target --initial_fuzz_cmd "afl-fuzz -i in -o fuzz_target -d ./target @@" --initial_budget 1800 --budget 86400 --post_mutant_cmd "cp fuzz_target/default/crashes*/id* fuzz_target/default/queue/ 2>/dev/null; rm -rf fuzz_target/default/crashes*"
~~~

(AFL++ keeps its output in `fuzz_target/default/`, and on a resume moves old crashes to `crashes.<date>`; with classic AFL the paths are `fuzz_target/crashes*` and `fuzz_target/queue`.)

That will 1) create a directory `fuzz_target` and use AFL to fuzz `target` for 30 minutes, then 2) switch to fuzzing a series of mutants of `target` for five minutes each before 3) finally switching back to fuzzing using AFL on the original `target`.  The total time spent fuzzing will be 24 hours, and MuttFuzz will spend half that time fuzzing mutants.  The `--post_mutant_cmd` handles the fact that things that crash some mutants may not crash the real `target`.   AFL++ removes crashes that don't crash the current version of a program, but we want them in the queue to explore.   When you're done fuzzing, you'll want to look in both `crashes` and `queue` for possible crashing inputs for `target`, due to the same issue.

If your executable is built with debug info (`-g`), use `--debug_info_only` (or `--source_only_mutate` with your source directory) so that only your code is mutated. Instrumented binaries contain a lot of fuzzer and sanitizer runtime code (with ASan, often most of the branches in the binary), and MuttFuzz's built-in list of runtime function names cannot cover all of it; MuttFuzz prints a warning when it looks like this is happening.

MuttFuzz writes mutants and other copies of the executable into a temporary `.muttfuzz_*` directory next to the executable (so that directory must be writable), so several MuttFuzz runs can share a machine.

You can likely improve your fuzzing if you can provide MuttFuzz with commands to 1) throw out mutants that aren't even reachable in the current corpus and 2) throw out mutants that already trigger a crash.  The first case is likely to be almost always helpful; the second is less certain.  These effects are achieved by, respectively, the `--reachability_check_cmd` and `--prune_mutants_cmd` arguments.  Both should tell MuttFuzz how to execute the current corpus, with this being done in such a way that if there is a crash, the output is a non-zero return value from the command.  In the reachability case, non-zero means the mutant is reached (we replace the mutant with a HALT) and in the pruning case (which uses the actual mutant) non-zero means the mutant induces crashes and should be skipped. For the reachability check to mean anything, the corpus it runs must not crash or hang the *original* program (keep crashing inputs out of the queue, or have the command skip them); MuttFuzz checks this once before fuzzing mutants and warns if the check already fails on the unmutated executable.

### Live mutants, frontier mutants, and adaptive time per mutant

Three optional modes change how mutants are chosen and run; each can be used alone or together.

* `--live` runs the fuzzer once for the whole budget (the `--initial_fuzz_cmd`, or the fuzzer command), and switches each mutant into its running processes instead of restarting the fuzzer on a mutated executable. A mutant only changes a few bytes of already-instrumented code, so its coverage map is laid out exactly like the original's, and the fuzzer keeps its queue and scheduling state across mutants (restarting a fuzzer throws that state away, which can cost more than the mutants gain). The bytes are written through `/proc/<pid>/mem` into the fuzzer's processes that run the executable: for AFL-style fork servers, the fork server (so every later child runs the mutant) and any persistent-mode child; for in-process fuzzers like libFuzzer, the fuzzer itself. They are re-applied about once a second, so processes the fuzzer restarts from disk during a mutant's window run it too. The file on disk stays the original. This needs ptrace-level access to the fuzzer's processes, which MuttFuzz has as their ancestor under the default Linux setting; in Docker you may need `--cap-add=SYS_PTRACE`. One caveat: the fuzzer's record of coverage seen so far persists across mutants, so an edge first reached under a mutant is not "new" when an input later reaches it on the original.

* `--frontier_check` chooses mutants at the coverage frontier: conditional jumps the current corpus reaches but only ever takes one way, mutated to force the other way (an unconditional jump, or NOPs). It uses `--reachability_check_cmd` with HALT probes on the real executable: a HALT after the jump (does the corpus fall through?), the same with the jump's condition inverted (is it ever taken?), and, for jumps never taken, a HALT on the target (is that code reached some other way? if so it is not a frontier). Candidates are explored by group testing (one run with a HALT on each jump of a large group tells whether any is reached at all), results are cached, and frontier jumps are re-checked before use since the corpus keeps growing. If no frontier jump is found within `--frontier_probes` corpus runs (default 30), a random mutant is used. Frontier mutants target control-flow blockers; mutants that matter through data-dependent behavior are correspondingly less likely to be chosen.

* `--progress_cmd CMD` makes the time per mutant adaptive. `CMD` prints a number that grows as the fuzzer makes progress (for AFL++, e.g. `grep corpus_count out/default/fuzzer_stats`; for libFuzzer, `ls corpus | wc -l`). Each mutant runs for `--time_per_mutant` seconds, then is extended one `--progress_window` (default: `--time_per_mutant`) at a time while the number grew during the last window, up to `--max_time_per_mutant` (default 4 x `--time_per_mutant`) and the end of the mutant phase. Mutants that are not helping what the fuzzer is exploring at the moment are dropped after the minimum; productive ones get the time to pay off.

```muttfuzz --help``` will give details on other options.  One nice thing is to print out status (e.g., cat the AFL stats file, or ls | wc -l on crashes/queue) after each fuzzing run.

This example shows how to use MuttFuzz with AFL (or AFLplusplus) but using it with libFuzzer or Honggfuzz should be approximately as easy, or easier.

**Q**: How good is MuttFuzz?

**A**: We're not sure yet, experiments are pending.  We know that a source-based variant of the same technique, somewhat less tuned, outperformed AFLplusplus on FuzzBench, so we're optimistic that this is both easier to use and even more effective than that.  In our limited experiments thus far, it is dramatically improving fuzzing a toy benchmark using AFL, much more than the source-based approach did.  Additionally, and more interestingly, one realistic "anecdata" suggests it's well worth trying out on stubborn fuzzing targets.  An extremely subtle bug in a Turbo Boyer-Moore-Horspool search implementation, originally detected after literally months of fuzzing and billions of executions, via this harness (https://github.com/agroce/deepstate-boyer-moore-horspool/), can be detected easily and consistently using MuttFuzz.  Your target may have similar behaviors that are rendered much easier to detect via mutant fuzzing.  To try it, grab the deepstate AFL++ Docker image (agroce/deepstate_examples_aflpp) and do:

```
cd ~/examples/deepstate-boyer-moore-horspool/
export FUZZ_DIR=muttfuzz_bmh
muttfuzz "deepstate-afl ./testhorspool_AFL -o $FUZZ_DIR" ./testhorspool_AFL --budget 86400 --time_per_mutant 600 --fraction_mutant 0.90 --initial_fuzz_cmd "rm -rf $FUZZ_DIR; deepstate-afl ./testhorspool_AFL -o $FUZZ_DIR" --initial_budget 3600
```

**Q**: Why is fuzzing mutants helpful?

**A**: For more information on that, and on the source-based version of this idea, see [our paper in submission to ACM TOSEM, the final version of our FUZZING'22 registered report](https://github.com/agroce/fuzzing22report/blob/master/tosem/currentdraft.pdf).  Long story short, we speculate that some mutants remove common barriers to fuzzing, and/or allow fuzzing to find branches "non-chronologically."

**Q**: Hey, you said I could use MuttFuzz to estimate a mutation score?

**A**: Yes, just use a fuzzing command that does nothing but check a mutant for detection (something like the commands used for reachability and pruning) that returns non-zero on detected mutants, and add the `--score` option.  Note that MuttFuzz uses a peculiar and biased set of mutation operators, and may score the same mutant multiple times, so take this value with a grain of salt.  You can also have the fuzzing command do some actual fuzzing, and then check for detection after the fuzzing.

Note that reachability and pruning work as usual here.  Pruning will seldom be needed, but there may be some notion of invalid mutants you want to use.  Reachability lets you compute  a score over mutants the corpus actually executes, which is usually more informative than including mutants not even executed.  The distinction is between "mutation score" and "covered mutation score" (see [this paper](https://agroce.github.io/issre23.pdf)).  Note that MuttFuzz, when a reachability check is included, always shows a running and final total of estimated coverage of mutants.  In principle a mutation score estimate could be produced from the prune checks during fuzzing campaigns, but the fact that fuzzing (we hope) changes the power of the corpus will make this total unstable and hard to interpret.

While this isn't the main focus of MuttFuzz, the Bitcoin Core fuzzing team has done some intial work experimenting with using this to evaluate changes in their fuzz efforts for long-running (e.g. OSS-Fuzz) campaigns with extensive corpus history.  Paper/details forthcoming.

**Q**: Why "MuttFuzz"?

**A**: When I (Alex) created the repo, I made a typo, but I liked it.  Certainly memorable compared to "mutfuzz" for "mutant fuzzer".

-------------------------------

Thanks to: Peter Goodman @ Trail of Bits, Kush Jain, and Richard Hipp.
Also thanks to kosak, scottd, and roc.
