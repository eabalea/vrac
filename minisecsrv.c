static char rcsid[] = "$Id: minisecsrv.c,v 1.3 2013/03/27 18:37:06 eabalea Exp $";

/*
 * encrypt len data\n
 * ok len data\n
 * nok code reasontext\n
 *
 * decrypt len data\n
 * ok len data\n
 * nok code reasontext\n
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <openssl/crypto.h>
#include "utils.h"
#include "config.h"

#define detach if (fork()); else for (;; exit(0))


/**************
 * Global variables (bad)
 **************/
minisecsrv_cfg *cfg = NULL;


/******
 * SIGQUIT signal handler
 * It should clean memory, and quit.
 ******/
void SIGQUIThandler(int signum)
{
  int i;

  if (cfg->debug)
    printf("Entering SIGQUIThandler()\n");
  
  OPENSSL_cleanse(cfg->key, cfg->enc->key_len);
  OPENSSL_cleanse(cfg->passphrase, strlen(cfg->passphrase)+1);

  exit(-1);
}


/******
 * Everything starts here...
 ******/
int main(int argc, char **argv)
{
  BIO *abio = NULL;
  BIO *biobuf = NULL;
  int rc = 0;

  if (rc = init(argc, argv, &cfg))
    goto done;

#if 0
  {
    unsigned char in[1024];
    unsigned char *out = NULL;
    unsigned int inl = 0;
    unsigned int outl = 0;
    unsigned int i;

    memcpy(in, "Hello, demo world!", 18);
    inl = 18;

    printf("Encrypting \"Hello, demo world!\".\n");
    dofullencrypt(cfg, in, inl, &out, &outl);
    for(i = 0; i < outl; i++)
      printf("%c", out[i]);
    printf("\n");

    memcpy(in, out, outl);
    inl = outl;
    free(out);
    out = NULL;

    printf("Decrypting the result.\n");
    dofulldecrypt(cfg, in, inl, &out, &outl);
    for(i = 0; i < outl; i++)
      printf("%c", out[i]);
    printf("\n");
  }
#endif

  printf("Ready to serve...\n");

  signal(SIGQUIT, SIGQUIThandler);
  
  /* We need a BIO to accept connections */
  abio = BIO_new_accept(cfg->hostport);
  if (!abio)
  {
    fprintf(stderr, "Unable to create a new accept BIO.\n");
    rc = -1;
    goto done;
  }
  BIO_set_bind_mode(abio, BIO_BIND_REUSEADDR);
  if (BIO_do_accept(abio) <= 0)
  {
    fprintf(stderr, "Unable to accept connections.\n");
    rc = -1;
    goto done;
  }

  /* And we add a buffer BIO that will be duplicated for each created
   * connections
   */
  biobuf = BIO_new(BIO_f_buffer());
  if (!biobuf)
  {
    fprintf(stderr, "Unable to create a buffer BIO.\n");
    rc = -1;
    goto done;
  }
  BIO_set_accept_bios(abio, biobuf);

  /* Release all rights and go background */
  if (!cfg->debug)
  {
    changeidentity(cfg->user, cfg->group);
    beadaemon();
  }

  while (1)
  {
    BIO *cbio = NULL;

    /* This is a blocking call */
    BIO_do_accept(abio);

    /* A connection has arrived, detach the corresponding BIO */
    cbio = BIO_pop(abio);
//    detach {
      unsigned char command[8] = "";
      unsigned char len[8] = "";
      BIO *content = NULL;

      rc = BIO_gets(cbio, command, 8);
      rc = BIO_gets(cbio, len, 8);
      rc = BIO_puts(cbio, "Gotcha\n");
      rc = BIO_puts(cbio, command);
      rc = BIO_puts(cbio, "\n");
      rc = BIO_puts(cbio, len);
      rc = BIO_puts(cbio, "\n");
      BIO_free_all(cbio);
//    }
  }
  
done:
  BIO_free(abio);
  return rc;
}
