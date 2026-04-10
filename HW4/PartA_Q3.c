#include <stdio.h>
#include <limits.h>

int f(int x) {
  int y=~x;
  // printf("x=%d, y=%d, x+y=%d\n", x, y, x+y);
  // printf("%d\n", (-1)%2);
  if ((x+y)%2==1) {
    if (((x<<15)>>15)==0) {
      return 0;
    } else {
      return 1;
    }
  } else {
    // printf("x+y is even\n");
    if (((y<<31)>>31)==0) {
      return 0;
    } else {
      return 1;
    }
  }
}

int main() {
  // int x;
  // scanf("%d", &x);
  printf("%d\n", f(3385));

  // for (int i = INT_MIN; i < INT_MAX; i++) {
  //   int c = f(i);
  //   int d = i & 1;
  //   if (c == d) {
  //     printf("WACK\n");
  //   }
  // }

  return 0;
}