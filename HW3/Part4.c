#include <stdio.h>
#include <string.h>
int main()
{
  int i, j, la, lb, num = 0;
  char c, a[12], b[45];
  while ((c = getchar()) != '\n')
    a[num++] = c;
  a[num] = '\0';
  printf("The str1 is:\n");
  printf(a);
  num = 0;
  while ((c = getchar()) != '\n')
    b[num++] = c;
  b[num] = '\0';
  printf("\nThe str2 is:\n");
  printf(b);
  la = strlen(a);
  lb = strlen(b);
  for (i = 0; (lb - i) >= la; i++)
  {
    if (b[i] == a[0])
    {
      for (j = 0; j < la; j++)
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
