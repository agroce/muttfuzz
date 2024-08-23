#include <assert.h>

int main() {
  int a = 20;
  if (a < 10) {
    assert(0);
  }

  if (a > 100) {
    assert(0);
  }

  if (a != 20) {
    assert(0);
  }
}
