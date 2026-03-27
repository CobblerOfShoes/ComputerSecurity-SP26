#include <stdio.h>
#include <string.h>

void length_check(char *str)
{
  printf("The concatenated string is: %s \nThe length of the concatenated string is: %d\n",str, (int) strlen(str));
}

int insecure_main()
{
  char result[10];
  char str1[10];
  char str2[10];
  memset(result,'\0',10);
  // Vulnerability 1: Don't use gets, use fgets (no bounds checking)
  gets(str1);
  // Vulnerability 2: Don't use gets
  gets(str2);
  // Vulnerability 3: Use strncpy instead for bounds checking
  strcpy(result, str1);
  // Vulnerability 4: Use strncat instead for bounds checking
  strcat(result, str2);
  length_check(result);
  return(0);
}

// ----------------------------------------------------------------

int secure_main()
{
  char result[10] = {0};
  char buffer[BUFSIZ] = {0};
  char str1[10] = {0};
  char str2[10] = {0};

  printf("Please enter the first string (max 9 characters):\n");
  if (!fgets(buffer, BUFSIZ, stdin)) {
    fprintf(stderr, "Error reading first string\n");
    return(1);
  }
  sscanf(buffer, "%9s", str1);

  printf("Please enter the second string (max 9 characters):\n");
  if (!fgets(buffer, BUFSIZ, stdin)) {
    fprintf(stderr, "Error reading second string\n");
    return(1);
  }
  sscanf(buffer, "%9s", str2);

  str1[strcspn(str1, "\n")] = '\0';
  str2[strcspn(str2, "\n")] = '\0';
  strncpy(result, str1, sizeof(result) - 1);
  strncat(result, str2, sizeof(result) - strlen(result) - 1);
  length_check(result);
  return(0);
}

// Sample inputs:
//  1) Overflowing both buffers
//     ABCDABCDABCD
//     123412341234
//  2) Overflowing output with second buffer
//     Hello
//     World!
//  3) Overflowing only first buffer
//     LengthyInput
//     Short
int main()
{
  printf("Insecure version:\n");
  insecure_main();

  printf("\nSecure version:\n");
  secure_main();
}