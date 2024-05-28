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
muttfuzz "afl-fuzz -i- -o fuzz_target -d ./target @@" target --initial_fuzz_cmd "afl-fuzz -i in -o fuzz_target -d ./target @@" --initial_budget 1800 --budget 86400 --post_mutant_cmd "cp fuzz_target/crashes.*/id* fuzz_target/queue/; rm -rf fuzz_target/crashes.*"
~~~

That will 1) create a directory `fuzz_target` and use AFL to fuzz `target` for 30 minutes, then 2) switch to fuzzing a series of mutants of `target` for five minutes each before 3) finally switching back to fuzzing using AFL on the original `target`.  The total time spent fuzzing will be 24 hours, and MuttFuzz will spend half that time fuzzing mutants.  The `--post_mutant_cmd` handles the fact that things that crash some mutants may not crash the real `target`.   AFL++ removes crashes that don't crash the current version of a program, but we want them in the queue to explore.   When you're done fuzzing, you'll want to look in both `crashes` and `queue` for possible crashing inputs for `target`, due to the same issue.

You can likely improve your fuzzing if you can provide MuttFuzz with commands to 1) throw out mutants that aren't even reachable in the current corpus and 2) throw out mutants that already trigger a crash.  The first case is likely to be almost always helpful; the second is less certain.  These effects are achieved by, respectively, the `--reachability_check_cmd` and `--prune_mutants_cmd` arguments.  Both should tell MuttFuzz how to execute the current corpus, with this being done in such a way that if there is a crash, the output is a non-zero return value from the command.  In the reachability case, non-zero means the mutant is reached (we replace the mutant with a HALT) and in the pruning case (which uses the actual mutant) non-zero means the mutant induces crashes and should be skipped.

```muttfuzz --help``` will give details on other options.  One nice thing is to print out status (e.g., cat the AFL stats file, or ls | wc -l on crashes/queue) after each fuzzing run.

This example shows how to use MuttFuzz with AFL (or AFLplusplus) but using it with libFuzzer or Honggfuzz should be approximately as easy, or easier.

**Q**: How good is MuttFuzz?

**A**: We're not sure yet, experiments are pending.  We know that a source-based variant of the same technique, somewhat less tuned, outperformed AFLplusplus on FuzzBench, so we're optimistic that this is both easier to use and even more effective than that.  In our limited experiments thus far, it is dramatically improving fuzzing a toy benchmark using AFL, much more than the source-based approach did.

**Q**: Why is fuzzing mutants helpful?

**A**: For more information on that, and on the source-based version of this idea, see [our paper in submission to ACM TOSEM, the final version of our FUZZING'22 registered report](https://github.com/agroce/fuzzing22report/blob/master/tosem/currentdraft.pdf).  Long story short, we speculate that some mutants remove common barriers to fuzzing, and/or allow fuzzing to find branches "non-chronologically."

**Q**: Hey, you said I could use MuttFuzz to estimate a mutation score?

**A**: Yes, just use a fuzzing command that does nothing but check a mutant for detection (something like the commands used for reachability and pruning) that returns non-zero on detected mutants, and add the `--score` option.  Note that MuttFuzz uses a peculiar and biased set of mutation operators, and may score the same mutant multiple times, so take this value with a grain of salt.  You can also have the fuzzing command do some actual fuzzing, and then check for detection after the fuzzing.

**Q**: Why "MuttFuzz"?

**A**: When I (Alex) created the repo, I made a typo, but I liked it.  Certainly memorable compared to "mutfuzz" for "mutant fuzzer".

-------------------------------

Thanks to: Peter Goodman @ Trail of Bits, Kush Jain, and Richard Hipp.
Also thanks to kosak, scottd, and roc.
