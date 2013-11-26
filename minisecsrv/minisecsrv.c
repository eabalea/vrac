static char rcsid[] = "$Id: minisecsrv.c,v 1.5 2013/03/28 15:49:17 eabalea Exp $";

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
 * Read the request from the socket, do the job, return the result.
 * This version is super dumb, pure serial.
 ******/
int processrequest(BIO *cbio)
{
  unsigned char command[8] = "";
  unsigned char sep;
  unsigned char len_s[9] = "";
  unsigned char dummystr[9];
  unsigned int len = 0;
  unsigned char *datain = NULL;
  unsigned int datainl = 0;
  unsigned char *dataout = NULL;
  unsigned int dataoutl = 0;
  int rc = 0;

  memset(command, 0, sizeof(command));
  memset(len_s, 0, sizeof(len_s));

  /* Reading protocol elements (very dumb version) */
  if ((rc = BIO_read(cbio, command, 7)) <= 0)
  { rc = -1; goto done; }
  if ((rc = BIO_read(cbio, &sep, 1)) <= 0)
  { rc = -1; goto done; }
  if (sep != ' ')
  { rc = -1; goto done; }
  if (!strncmp(command, "encrypt", 7) && !strncmp(command, "decrypt", 7))
  { rc = -1; goto done; }
  if ((rc = BIO_read(cbio, len_s, 8)) <= 0)
  { rc = -1; goto done; }
  if ((rc = BIO_read(cbio, &sep, 1)) <= 0)
  { rc = -1; goto done; }
  if (sep != ' ')
  { rc = -1; goto done; }

  /* "len" field of the protocol is expressed in hex, malloc necessary
   * memory and read data
   */
  len = strtoul(len_s, NULL, 16);
  datain = malloc(len);
  if (!datain)
  { rc = -1; goto done; }
  datainl = BIO_read(cbio, datain, len);
  if (datainl != len)
  { rc = -1; goto done; }

  /* Check the final character (\n) */
  if ((rc = BIO_read(cbio, &sep, 1)) <= 0)
  { rc = -1; goto done; }
  if (sep != '\n')
  { rc = -1; goto done; }

  /* Do the work */
  if (!strncmp(command, "encrypt", 7))
    rc = dofullencrypt(cfg, datain, datainl, &dataout, &dataoutl);
  else
    rc = dofulldecrypt(cfg, datain, datainl, &dataout, &dataoutl);

  /* Send the result */
  if (!rc)
  {
    BIO_puts(cbio, "ok ");
    sprintf(dummystr, "%08x", dataoutl);
    BIO_puts(cbio, dummystr);
    BIO_puts(cbio, " ");
    BIO_write(cbio, dataout, dataoutl);
    BIO_puts(cbio, "\n");
  }
  else
  {
    BIO_puts(cbio, "nok ");
    sprintf(dummystr, "%08x", rc);
    BIO_puts(cbio, dummystr);
    BIO_puts(cbio, " ");
    BIO_puts(cbio, "No text description at the moment");
    BIO_puts(cbio, "\n");
  }

  rc = BIO_flush(cbio);

done:
  BIO_free_all(cbio);
  if (datain)
    free(datain);
  return rc;
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
  if ((rc = BIO_do_accept(abio)) <= 0)
  {
    fprintf(stderr, "Unable to accept connections.\n");
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

    /* A connection has arrived, detach the corresponding BIO and
     * process the request
     */
    cbio = BIO_pop(abio);
    processrequest(cbio);
  }
  
done:
  BIO_free(abio);
  return rc;
}
