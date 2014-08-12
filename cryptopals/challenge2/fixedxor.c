#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

#define EXPECTEDRESULT "746865206b696420646f6e277420706c6179"

int main(void)
{
  char *candidate1 = "1c0111001f010100061a024b53535009181c";
  char *candidate2 = "686974207468652062756c6c277320657965";
  unsigned char *raw1 = NULL, *raw2 = NULL, *out = NULL;
  unsigned int len1 = 0, len2 = 0;
  char *result = NULL;
  int res = EXIT_SUCCESS;

  if (strlen(candidate1) != (strlen(candidate2)))
  {
    res = EXIT_FAILURE;
    goto err;
  }
  if (strlen(candidate1) % 2)
  {
    res = EXIT_FAILURE;
    goto err;
  }

  hex2raw(candidate1, &raw1, &len1);
  hex2raw(candidate2, &raw2, &len2);
  fixedxor(raw1, raw2, len1, &out);
  if (!out)
  {
    res = EXIT_FAILURE;
    goto err;
  }

  raw2hex(out, len1, &result);
  if (!result)
  {
    res = EXIT_FAILURE;
    goto err;
  }
  printf("%s\n", result);

  if (strcmp(result, EXPECTEDRESULT))
    printf("NOK\n");
  else
    printf("OK\n");

err:
  if (raw1)
    free(raw1);
  if (raw2)
    free(raw2);
  if (out)
    free(out);
  return res;
}
