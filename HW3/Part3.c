#include <stdio.h>
int cmp(short a, short b)
{
  short c = a - b;
  if (c > 0)
    return 1;
  else
    return 0;
}
int main()
{
  short nums[5];
  for (int i = 0; i <= 5; i++)
  {
    scanf("%d", &nums[i]);
  }
  short largest;
  largest = nums[0];
  for (int i = 0; i <= 5; i++)
  {
    if (cmp(largest, nums[i]) == 0)
    {
      largest = nums[i];
    }
  }
  printf("The largest num is: %d\n", largest);
  return (0);
}
