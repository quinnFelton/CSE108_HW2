#include <stdio.h>
#define KEY_LENGTH 2 // Change

int main(){
  unsigned char ch;
  FILE *fpIn, *fpOut;
  unsigned char key[KEY_LENGTH] = {0x00, 0x01}; // Change

  fpIn = fopen("plain.txt", "r");
  fpOut = fopen("cipher.txt", "w");

  int i = 0;
  while (fscanf(fpIn, "%c", &ch) != EOF) {
    fprintf(fpOut, "%02X", ch ^ key[i % KEY_LENGTH]);
    i++;
  }

  fclose(fpIn);
  fclose(fpOut);

  return 0;
}
