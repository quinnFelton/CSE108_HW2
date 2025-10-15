#include <stdio.h>
#define KEY_LENGTH 2 // Change

int main(){
  unsigned int ch;
  FILE *fpIn, *fpOut;
  unsigned char key[KEY_LENGTH] = {0x00, 0x01}; // Change

  fpIn = fopen("cipher.txt", "r");
  fpOut = fopen("decrypted.txt", "w");

  int i = 0;
  while (fscanf(fpIn, "%2x", &ch) != EOF) {
    fprintf(fpOut, "%c", ch ^ key[i % KEY_LENGTH]);
    i++;
  }

  fclose(fpIn);
  fclose(fpOut);

  return 0;
}
