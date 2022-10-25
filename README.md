MuttFuzz doggedly fuzzes for you, mutating the executable as it goes!

<img src="mutt.jpeg" alt="drawing" width="200"/>

---------------------------------

**FAQ**

**Q**:  Is this a mutation testing tool?

**A**:  No.  MuttFuzz is only mutating your code in order to fuzz it better.  You don't need to care about the mutants, you'll never see them.  Coverage and bugs will be for your fuzzed program.

**Q**: What fuzzing algorithm does MuttFuzz use?

**A**: MuttFuzz doesn't use a fuzzing algorithm.  MuttFuzz is a *meta-fuzzer*.  This means you tell MuttFuzz what fuzzer you're using (and how you call it), and where your executable is, and MuttFuzz will orchestrate a fuzzing campaign, doing some behind-the-scenes work on the fuzzed executable that is likely to improve the effectiveness of that fuzzing.  MuttFuzz should work with most popular fuzzing tools.

**Q**: What are major limitations of MuttFuzz?

**A**: Right now, MuttFuzz only works for x86 Linux, and MuttFuzz may not work well if 1) your fuzzer needs two executables (like Angora) or 2) your target program decompiles poorly using _objdump_.  That's it.

**Q: How do I install MuttFuzz?**

**A**:

~~~
git clone https://github.com/agroce/muttfuzz.git
cd muttfuzz
python3 setup.py install
~~~

should do it on most linux setups.  Right now, MuttFuzz doesn't have any serious dependencies.  Once it's more stable, it'll probably be on pip, also.

**Q: How do I use MuttFuzz?** 

**A**: Let's say you want to use AFL to fuzz a program whose compiled and AFL-instrumented executable is named `target` and which takes its input from `stdin`:

~~~
export AFL_SKIP_CRASHES=TRUE
muttfuzz "afl-fuzz -i- -o fuzz_target -d ./target @@" target --initial_fuzz_cmd "afl-fuzz -i in -o fuzz_target -d ./target @@" --initial_budget 1800 --budget 86400 --post_mutant_cmd "cp fuzz_target/crashes.*/id* fuzz_target/queue/; rm -rf fuzz_target/crashes.*"
~~~

That will 1) create a directory `fuzz_target` and use AFL to fuzz `target` for 30 minutes, then 2) switch to fuzzing a series of mutants of `target` for five minutes each before 3) finally switching back to fuzzing using AFL on the original `target`.  The total time spent fuzzing will be 24 hours, and MuttFuzz will spend half that time fuzzing mutants.  The `--post_mutant_cmd` and `AFL_SKIP_CRASHES` setting handles the fact that things that crash some mutants may not crash the real `target` and vice versa.  When you're done fuzzing, you'll want to look in both `crashes` and `queue` for possible crashing inputs for `target`, due to the same issue.

```muttfuzz --help``` will give details on other options.  One nice thing is to print out status (e.g., cat the AFL stats file, or ls | wc -l on crashes/queue) after each fuzzing run.

This example shows how to use MuttFuzz with AFL (or AFLplusplus) but using it with libFuzzer or Honggfuzz should be approximately as easy, or easier.

**Q**: How good is MuttFuzz?

**A**: We're not sure yet, experiments are pending.  We know that a source-based variant of the same technique, somewhat less tuned, outperformed AFLplusplus on FuzzBench, so we're optimistic that this is both easier to use and even more effective than that.  In our limited experiments thus far, it is dramatically improving fuzzing a toy benchmark using AFL, much more than the source-based approach did.

**Q**: Why is fuzzing mutants helpful?

**A**: For more information on that, and on the source-based version of this idea, see [our paper in submission to ACM TOSEM, the final version of our FUZZING'22 registered report](https://github.com/agroce/fuzzing22report/blob/master/tosem/currentdraft.pdf).  Long story short, we speculate that some mutants remove common barriers to fuzzing, and/or allow fuzzing to find branches "non-chronologically."

**Q**: Why "MuttFuzz"?

**A**: When I (Alex) created the repo, I made a typo, but I liked it.  Certainly memorable compared to "mutfuzz" for "mutant fuzzer".

-------------------------------

Thanks to: Peter Goodman @ Trail of Bits, Kush Jain, and Richard Hipp.
Also thanks to kosak, scottd, and roc.
