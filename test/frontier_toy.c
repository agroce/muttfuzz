/* Test program for frontier selection: every input file's first byte is checked
   against 'X'; the test corpus never starts with 'X', so that jump is on the frontier.
   rare() appends "RARE" to the file named by $FRONTIER_OUT when it runs. */
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) void rare(void) {
  const char *p = getenv("FRONTIER_OUT");
  if (p) { FILE *f = fopen(p, "a"); if (f) { fputs("RARE\n", f); fclose(f); } }
}

__attribute__((noinline)) int check(const char *buf, long n) {
  if (n > 0 && buf[0] == 'X') {
    rare();
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  char buf[64];
  for (int i = 1; i < argc; i++) {
    FILE *f = fopen(argv[i], "rb");
    if (!f) continue;
    long n = (long)fread(buf, 1, sizeof buf, f);
    fclose(f);
    check(buf, n);
  }
  return 0;
}
