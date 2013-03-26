static char rcsid[] = "$Id: minisecsrv.c,v 1.1 2013/03/26 23:32:31 eabalea Exp $";

/*
 * encrypt len data\n
 * ok encrypted len data\n
 * nok code reasontext\n
 *
 * decrypt len data\n
 * ok decrypted len data\n
 * nok code reasontext\n
 *
 * seal len data\n
 * ok sealed len data\n
 * nok code reasontext\n
 *
 * check len data\n
 * ok check len data\n
 * nok code reasontext\n
 */


/**************
 * Necessary include files
 **************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <signal.h>
#include <getopt.h>
#include <dirent.h>
#include "utils.h"
#include "config.h"


/**************
 * Global variables (bad)
 **************/
minisecsrv_cfg *cfg = NULL;


/******
 * void SIGQUIThandler(int signum)
 *
 * SIGQUIT signal handler
 * This one will release everything in memory, close and delete the named 
 * pipe, and quit the program.
 ******/
void SIGQUIThandler(int signum)
{
  int i;

  if (cfg->debug)
    printf("Entering SIGQUIThandler()\n");
  
  /* Terminate all pending actions, and quit properly */

  exit(-1);
}


/******
 * int main(int argc, char **argv)
 *
 * Everything starts here...
 ******/
int main(int argc, char **argv)
{
  FILE *f;
  unsigned char iv[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  unsigned char in[1024];
  unsigned char out[1024];
  unsigned int inl = 0;
  unsigned int outl = 0;
  unsigned int tmpl = 0;
  unsigned int i;
  int rc;

  init(argc, argv, &cfg);

  printf("Key: ");
  for(i = 0; i < cfg->enc->key_len; i++)
    printf("%02X ", cfg->key[i]);
  printf("\n");

  printf("Encrypting \"Hello, demo world!\".\n");
  memcpy(in, "Hello, demo world!", 18);
  inl = 18;
  dobarecrypt(cfg, iv, in, inl, out, &outl);
  for(i = 0; i < outl; i++)
    printf("%02X ", out[i]);
  printf("\n");

  printf("Decrypting the result.\n");
  memcpy(in, out, outl);
  inl = outl;
  dobaredecrypt(cfg, iv, in, inl, out, &outl);
  for(i = 0; i < outl; i++)
    printf("%02X ", out[i]);
  printf("\n");

  //printf("Ready to serve...\n");

  // signal(SIGHUP, SIGHUPhandler);
  signal(SIGQUIT, SIGQUIThandler);
  // signal(SIGPIPE, SIGPIPEhandler);
  
  //if (!debug)
  //  beadaemon();

  //while (1)
  //{
  //}
  
  return 0;
}
