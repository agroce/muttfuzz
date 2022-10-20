MuttFuzz doggedly fuzzes for you, mutating the executable as it goes!

Sample usage.  Assume we have an existing fuzzer run of afl-fuzz on target in fuzz_target:

~~~
mutfuzz "afl-fuzz -i- -o fuzz_target -d ./target @@" target --status_cmd "ls fuzz_target/queue/id* | wc -l" --time_per_mutant 60
~~~

Thanks to: Peter Goodman @ Trail of Bits, Kush Jain, and Richard Hipp.
Also thanks to kosak, scottd, dlc, and roc.
