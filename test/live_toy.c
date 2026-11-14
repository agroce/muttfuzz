#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
volatile int x = 1;
__attribute__((noinline)) int f(void) { if (x > 0) return 1; return 2; }
int main(int argc, char **argv) {
  for (;;) {
    pid_t p = fork();
    if (p == 0) { FILE *out = fopen(argv[1], "a"); fprintf(out, "%d\n", f()); fclose(out); _exit(0); }
    waitpid(p, 0, 0);
    usleep(20000);
  }
}
