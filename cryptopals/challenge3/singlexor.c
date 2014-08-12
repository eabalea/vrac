#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

int main(int argc, char **argv)
{
  char *candidate = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  unsigned char *raw = NULL;
  unsigned int len = 0, i;
  unsigned char key = 'X';
  char *dst = NULL;
  int res = EXIT_SUCCESS;

  if (argc > 1)
    key = argv[1][0];

  printf("Testing with key [%c]\n", key);

  hex2raw(candidate, &raw, &len);
  if (!raw)
  {
    res = EXIT_FAILURE;
    goto err;
  }

  for(i = 0; i < len; i++)
    raw[i] ^= key;

  raw2hex(raw, len, &dst);
  if (!dst)
  {
    res = EXIT_FAILURE;
    goto err;
  }

  printf("%s\n", dst);
  for(i = 0; i < len; i++)
    printf("%c", raw[i]);

err:
  return res;
}
