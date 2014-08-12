#include <string.h>
//#include <stdio.h>
#include <stdlib.h>

#define BASE64DICT "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define N2I(a) ((a)>'F'?((a)-'a')+10:((a)>'9'?((a)-'A')+10:(a)-'0'))
#define I2N(a) ((a)>9?((a)+'a')-10:(a)+'0')

void hex2raw(char *in, unsigned char **out, unsigned int *len)
{
  unsigned char *res = NULL;
  int i = 0;

  if (!in)
    goto err;
  if (strlen(in) % 2)
    goto err;
  for(i = 0; i < strlen(in); i++)
    if (   (in[i] < '0' && in[i] > '9')
	|| (in[i] < 'A' && in[i] > 'F')
	|| (in[i] < 'a' && in[i] > 'f'))
      goto err;
  res = malloc(strlen(in)/2);

  i = 0;
  while (*in) {
    unsigned int b = 0;
    b = (N2I(in[0]) << 4) + N2I(in[1]);
    in += 2;
    res[i++] = b;
  }

err:
  *out = res;
  if (!res)
    *len = 0;
  else
    *len = i;
}

void raw2hex(unsigned char *in, unsigned int len, char **out)
{
  char *res = NULL;
  int i = 0;

  if (!in)
    goto err;
  res = malloc(len*2+1);

  i = 0;
  for(i = 0; i < len; i++)
  {
    res[2*i] = I2N((in[i]&0xf0)>>4);
    res[2*i+1] = I2N(in[i]&0x0f);
  }
  res[2*i] = 0;

err:
  *out = res;
}

char *hex2b64(char *str)
{
  char *res = NULL;
  int i = 0, o = 0;
  char *base64set = BASE64DICT;
  unsigned char *raw = NULL;
  unsigned int len = 0;

  hex2raw(str, &raw, &len);
  if (!raw)
    goto err;
  res = malloc(len*2);
  while (i < len) {
    int padding = 0;
    unsigned int b1 = 0, b2 = 0, b3 = 0;

    b1 = raw[i++];
    if (i < len)
      b2 = raw[i++];
    else
      padding++;
    if (i < len)
      b3 = raw[i++];
    else
      padding++;

    res[o++] = base64set[(b1&0xfc)>>2];
    res[o++] = base64set[((b1&0x03)<<4) + ((b2&0xf0)>>4)];
    if (padding == 2)
      res[o++] = '=';
    else
      res[o++] = base64set[((b2&0x0f)<<2) + ((b3&0xc0)>>6)];
    if (padding)
      res[o++] = '=';
    else
      res[o++] = base64set[b3&0x3f];
  }
  res[o] = 0;
  free(raw);

err:
  return res;
}

void fixedxor(unsigned char *in1, unsigned char *in2, unsigned int len, unsigned char **out)
{
  unsigned char *res = NULL;
  unsigned int i;

  if (!in1 || !in2 || !len)
    goto err;

  res = malloc(len);

  for(i = 0; i < len; i++)
    res[i] = in1[i] ^ in2[i];

err:
  *out = res;
}

