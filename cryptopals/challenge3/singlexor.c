#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"

int scorephrase(unsigned char *str, int len)
{
  /* ETAOIN SHRDLU */
  int i;
  int score = 0;

  for(i = 0; i < len; i++)
  {
    if (toupper(str[i]) == 'E')
      score += 13;
    if (toupper(str[i]) == 'T')
      score += 12;
    if (toupper(str[i]) == 'A')
      score += 11;
    if (toupper(str[i]) == 'O')
      score += 10;
    if (toupper(str[i]) == 'I')
      score += 9;
    if (toupper(str[i]) == 'N')
      score += 8;
    if (toupper(str[i]) == ' ')
      score += 7;
    if (toupper(str[i]) == 'S')
      score += 6;
    if (toupper(str[i]) == 'H')
      score += 5;
    if (toupper(str[i]) == 'R')
      score += 4;
    if (toupper(str[i]) == 'D')
      score += 3;
    if (toupper(str[i]) == 'L')
      score += 2;
    if (toupper(str[i]) == 'U')
      score += 1;
    if (!isprint(str[i]))
      score = -1000;
  }
  return score;
}

int main(int argc, char **argv)
{
  char *candidate = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  unsigned char *raw = NULL;
  unsigned int len = 0, j;
//  unsigned char key = 'X';
  unsigned char key = 0;
  int i;
  char *dst = NULL;
  int res = EXIT_SUCCESS;
  unsigned char bestkey = 0;
  int bestscore = 0;

  if (argc > 1)
    candidate = argv[1];

  for(i = 'x'; i < 256; i++)
  {
    int currentscore = 0;

    hex2raw(candidate, &raw, &len);

    for(j = 0; j < len; j++)
      raw[j] ^= key;

    currentscore = scorephrase(raw, len);

    // printf("%X %c %d\n", key, key, currentscore);

    if (currentscore > bestscore)
    {
      bestscore = currentscore;
      bestkey = key;
    }

    key++;
  }

  printf("Best probable key: %X\n", bestkey);
  hex2raw(candidate, &raw, &len);
  for(j = 0; j < len; j++)
    raw[j] ^= bestkey;
  printf("%s\n", raw);

err:
  return res;
}
