//#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

#define EXPECTEDRESULT "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

int main(int argc, char **argv)
{
  char *res = NULL;
  char *candidate = NULL;

  if (argc == 1)
    candidate = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  else
    candidate = argv[1];

  res = hex2b64(candidate);
  if (res) {
    printf("%s\n", res);
    if (strcmp(res, EXPECTEDRESULT))
      printf("NOK\n");
    else
      printf("OK\n");
  }
  else {
    printf("Invalid input\n");
  }

  if (res)
    free(res);
  return EXIT_SUCCESS;
}
