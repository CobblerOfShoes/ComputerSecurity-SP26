#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>

int insecure_cmp(short a,short b){
  // Vulnerability 1: Integer overflow in subtraction
  // One possible set of inputs
  short c=a-b;
  if (c>0)
    return 1;
  else
    return 0;
}

int insecure_main(){
  short nums[5];
  // Vulnerability 2: Off by one error, allowing input of 6 numbers instead of 5
  for (int i=0;i<=5;i++){
    // Vulnerability 3: No input validation, allowing for integer overflow
    scanf("%d",&nums[i]);
  }
  short largest;
  largest=nums[0];
  // Vulnerability 4: Off by one error, allowing for comparison of 6 numbers instead of 5
  for (int i=0;i<=5;i++){
    if (insecure_cmp(largest,nums[i])==0){
      largest=nums[i];
    }
  }
  printf("The largest num is: %d\n",largest);
  return(0);
}

// --------------------------------------------------------------------

int secure_cmp(short a,short b){
  if (a>b)
    return 1;
  else
    return 0;
}

int secure_short_input(short *num)
{
  long input;
  char buffer[BUFSIZ] = {0};

  errno = 0;

  if (!fgets(buffer, BUFSIZ, stdin)) {
    fprintf(stderr, "Error reading input\n");
    return(1);
  }

  char *endptr;
  input = strtol(buffer, &endptr, 10);

  // Check for various possible errors
  if (endptr == buffer || *endptr != '\n') {
    fprintf(stderr, "Invalid input (empty or non-numeric)\n");
    return(1);
  }

  if ( (errno == ERANGE) ||(input > SHRT_MAX) || (input < SHRT_MIN) ) {
    fprintf(stderr, "Input out of range\n");
    return(1);
  }

  *num = (short)input;
  return(0);
}

int secure_main(){
  printf("Please enter 5 numbers within the range of %d to %d:\n", SHRT_MIN, SHRT_MAX);

  short nums[5];
  for (int i=0;i<5;i++){
    if (secure_short_input(&nums[i]) == 0) {
      continue;
    } else {
      printf("Please try again.\n");
      i--; // Decrement i to retry the input for the current index
    }
  }

  short largest;
  largest=nums[0];
  for (int i=0;i<5;i++){
    if (secure_cmp(largest,nums[i])==0){
      largest=nums[i];
    }
  }

  printf("The largest num is: %d\n",largest);
  return(0);
}

int main(){
  printf("Insecure version:\n");
  insecure_main();

  // Eat up newlines to prevent issues with subsequent input
  int c;
  while ((c = getchar()) != '\n' && c != EOF) { }

  printf("\nSecure version:\n");
  secure_main();
  return(0);
}