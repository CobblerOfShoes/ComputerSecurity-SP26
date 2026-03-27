#include <stdio.h>
#include <string.h>
int main()
{
  int i, j, la, lb, num = 0;
  char c, a[12], b[45];
  // Vulnerability 1: No bounds checking on input, allowing for buffer overflow
  while ((c = getchar()) != '\n')
    a[num++] = c;
  // Vulnerability 2: Same as 1 really, but could be writing out of bounds of a if num > 11
  a[num] = '\0';
  printf("The str1 is:\n");
  printf("%s\n", a);
  num = 0;
  // Vulnerability 3: No bounds checking on input, allowing for buffer overflow
  while ((c = getchar()) != '\n')
    b[num++] = c;
  // Vulnerability 4: Same as 3 really, but could be writing out of bounds of b if num > 44
  b[num] = '\0';
  printf("\nThe str2 is:\n");
  printf("%s\n", b);
  la = strlen(a);
  lb = strlen(b);
  for (i = 0; (lb - i) >= la; i++)
  {
    if (b[i] == a[0])
    {
      for (j = 0; j < la; j++)
        // Vulnerability 5: No bounds checking to see if i + j is out of bounds of b
        if (b[i + j] != a[j])
          break;
      if (j == la)
      {
        printf("\nPosition: %d\n", i);
        return 0;
      }
    }
  }
  printf("\nNot found!\n");
}
