// Pascal Triangle

#include <stdio.h>

void pascal_triangle(int height) {
  int final_row_width = height * 2 - 1;

  for (int i = 0; i < height; i++) {
    int num_elements = i + 1;
    int row_width = num_elements * 2 - 1;
    int padding = (final_row_width - row_width) / 2;

    // Print leading spaces
    for (int j = 0; j < padding; j++) {
      printf(" ");
    }

    // Print the numbers in the current row
    int value = 1; // First value in each row is always 1
    for (int j = 0; j < num_elements; j++) {
      printf("%d ", value);
      value = value * (i - j) / (j + 1); // Calculate the next value using the previous one
    }

    printf("\n"); // Move to the next line after printing each row
  }
}

int main() {
  int height;
  printf("Enter the height of the Pascal Triangle: ");
  scanf("%d", &height);
  pascal_triangle(height);
  return 0;
}