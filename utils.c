static char rcsid[] = "$Id: utils.c,v 1.2 2013/03/27 18:37:06 eabalea Exp $";


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include "config.h"
#include "utils.h"


/******
 * This function displays a help text and quits the program.
 ******/
void printhelp(void)
{
  printf("minisecsrv [option...]\n");
  printf("\n");
  printf("  -c,--config      config file (default is %s)\n", MINISECSRV_DEFAULTRCFILE);
  printf("  -d,--debug       activate debug mode (no daemon, and some messages)\n");
  printf("  --printcheck     print passphrase checking information\n");
  exit(1);
}


/******
 * Do what is necessary to become a daemon: detach from the terminal,
 * leave session and group leadership, close std{in,out,err}, ...
 ******/
void beadaemon(void)
{
  pid_t son;
  int result = 0;

  /* Start by a fork(), the father must die, the son is no more
   * process group leader.
   */
  son = fork();
  switch (son)
  {
    case -1:
      fprintf(stderr, "Unable to fork() to go into back-ground\n");
      result = -1;
      goto done;
      break;

    case 0:
      break;
      
    default:
      /* Let's call _exit() rather that exit(), to avoid some bad side
       * effects.
       */
      _exit(0);
      break;
  }

  /* Let's call setsid() to create a new session and become its
   * leader, create a new process group and become its leader, and
   * detach completely from the terminal.
   */
  if (setsid() == -1)
  {
    fprintf(stderr, "Unable to call setsid()\n");
    result = -1;
    goto done;
  }

  /* Let's call fork() again, the father must die. After this, the new
   * process is leader of nothing, has no terminal attached to it, and
   * has no way to attach to a terminal.
   */
  son = fork();
  switch (son)
  {
    case -1:
      fprintf(stderr, "Unable to fork() again\n");
      result = -1;
      goto done;
      break;

    case 0:
      break;
      
    default:
      /* Again, let's call _exit() rather than exit(). */
      _exit(0);
      break;
  }

  /* ToDo: optional, do a chdir("/") to avoid blocking an unmount()
   * from the system admin. If we do this, then all the file names
   * must be converted into absolute file names.
   */

  /* ToDo: optional, do an umask(0) to control the file permissions on
   * creation.
   */

  /* Let's close the file descriptors 0, 1, and 2 (stdin, stdout and
   * stderr).
   */
  close(0);
  close(1);
  close(2);

  /* Open stdin, stdout and stderr to /dev/null */
  open("/dev/null", O_RDWR);
  (void)dup(0);
  (void)dup(0);

done:
  if (result)
    exit(result);
}


/******
 * Change current identity, resolving named group and user.
 ******/
int changeidentity(char *user, char *group)
{
  struct group *grpid = NULL;
  struct passwd *pwdid = NULL;
  int rc = 0;

  /* If a group name is given, try to use it */
  if (group)
  {
    /* Start by asking the system to find the group */
    grpid = getgrnam(group);
    if (!grpid)
    {
      printf("Unable to find group named \"%s\".\n", group);
      rc = MINISECSRV_ERR_CANTFINDGROUP;
      goto done;
    }

    /* And then change the current group */
    if (setgid(grpid->gr_gid))
    {
      printf("Unable to change group.\n");
      rc = MINISECSRV_ERR_CANTCHANGEGROUP;
      goto done;
    }
  }

  /* If a user name is given, try to use it */
  if (user)
  {
    /* Start by asking the system to find the user */
    pwdid = getpwnam(user);
    if (!pwdid)
    {
      printf("Unable to find user named \"%s\".\n", user);
      rc = MINISECSRV_ERR_CANTFINDUSER;
      goto done;
    }

    /* And then change the current user */
    if (setuid(pwdid->pw_uid))
    {
      printf("Unable to change user.\n");
      rc = MINISECSRV_ERR_CANTCHANGEUSER;
      goto done;
    }
  }

done:
  return rc;
}


/******
 * Generate a pseudo-random IV
 ******/
int generaterandomiv(minisecsrv_cfg *cfg, unsigned char *iv)
{
  int rc = 0;
  if (RAND_pseudo_bytes(iv, cfg->enc->iv_len) == -1)
  {
    rc = MINISECSRV_ERR_RAND;
    goto done;
  }

done:
  return rc;
}


/******
 * Do the encryption, the caller has to give the iv.
 ******/
int dobareencrypt(minisecsrv_cfg *cfg, unsigned char *iv, unsigned char *in, unsigned int inl, unsigned char *out, unsigned int *outl)
{
  EVP_CIPHER_CTX *ctx = NULL;
  unsigned int tmpl = 0;
  int rc = 0;

  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);

  if (!EVP_EncryptInit_ex(ctx, cfg->enc, NULL, cfg->key, iv))
  {
    rc = MINISECSRV_ERR_ENCRYPTINIT;
    goto done;
  }

  if (!EVP_EncryptUpdate(ctx, out, outl, in, inl))
  {
    rc = MINISECSRV_ERR_ENCRYPTUPDATE;
    goto done;
  }

  if (!EVP_EncryptFinal_ex(ctx, out+(*outl), &tmpl))
  {
    rc = MINISECSRV_ERR_ENCRYPTFINAL;
    goto done;
  }

  (*outl) += tmpl;

done:
  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}


/******
 * Do the decryption, the caller has to give the iv.
 ******/
int dobaredecrypt(minisecsrv_cfg *cfg, unsigned char *iv, unsigned char *in, unsigned int inl, unsigned char *out, unsigned int *outl)
{
  EVP_CIPHER_CTX *ctx = NULL;
  unsigned int tmpl = 0;
  int rc = 0;

  ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);

  if (!EVP_DecryptInit_ex(ctx, cfg->enc, NULL, cfg->key, iv))
  {
    rc = MINISECSRV_ERR_DECRYPTINIT;
    goto done;
  }

  if (!EVP_DecryptUpdate(ctx, out, outl, in, inl))
  {
    rc = MINISECSRV_ERR_DECRYPTUPDATE;
    goto done;
  }

  if (!EVP_DecryptFinal_ex(ctx, out+(*outl), &tmpl))
  {
    rc = MINISECSRV_ERR_DECRYPTFINAL;
    goto done;
  }

  (*outl) += tmpl;

done:
  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}


/******
 * Encode some data into base64
 ******/
int dobase64encode(minisecsrv_cfg *cfg, unsigned char *in, unsigned int inl, unsigned char *out, unsigned int *outl)
{
  BIO *b64 = NULL,
      *biomem = NULL;
  int rc = 0;

  /* Create a BIO to receive base64-encoded data */
  biomem = BIO_new(BIO_s_mem());
  if (!biomem)
  {
    rc = MINISECSRV_ERR_BASE64_CANTCREATEBIO;
    goto done;
  }

  /* Create the base64 encoder */
  b64 = BIO_new(BIO_f_base64());
  if (!b64)
  {
    rc = MINISECSRV_ERR_BASE64_CANTCREATEBIO;
    goto done;
  }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  /* Associate both */
  BIO_push(b64, biomem);

  /* Push data into the base64 encoder */
  if (BIO_write(b64, in, inl) != inl)
  {
    rc = MINISECSRV_ERR_BASE64_WRITEERR;
    goto done;
  }
  if (BIO_flush(b64) != 1)
  {
    rc = MINISECSRV_ERR_BASE64_FLUSHERR;
    goto done;
  }

  /* And read the result from the biomem pool */
  *outl = BIO_ctrl_pending(biomem);
  if (BIO_read(biomem, out, *outl) != *outl)
  {
    rc = MINISECSRV_ERR_BASE64_CANTREAD;
    goto done;
  }

done:
  BIO_free(b64);
  BIO_free(biomem);
  return rc;
}


/******
 * Decode the base64 given data
 ******/
int dobase64decode(minisecsrv_cfg *cfg, unsigned char *in, unsigned int inl, unsigned char *out, unsigned int *outl)
{
  BIO *b64 = NULL,
      *biomemin = NULL,
      *biomemout = NULL;
  unsigned char buf[1024];
  int tmpsize;
  int rc = 0;

  /* Create a BIO to receive base64-encoded data */
  biomemin = BIO_new(BIO_s_mem());
  if (!biomemin)
  {
    rc = MINISECSRV_ERR_BASE64_CANTCREATEBIO;
    goto done;
  }
  BIO_set_mem_eof_return(biomemin, 0);

  /* Create a BIO to receive base64-decoded data */
  biomemout = BIO_new(BIO_s_mem());
  if (!biomemout)
  {
    rc = MINISECSRV_ERR_BASE64_CANTCREATEBIO;
    goto done;
  }

  /* Create the base64 decoder */
  b64 = BIO_new(BIO_f_base64());
  if (!b64)
  {
    rc = MINISECSRV_ERR_BASE64_CANTCREATEBIO;
    goto done;
  }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

  /* Associate them */
  BIO_push(b64, biomemin);

  /* Push base64 data into the biomem */
  if (BIO_write(biomemin, in, inl) != inl)
  {
    rc = MINISECSRV_ERR_BASE64_WRITEERR;
    goto done;
  }
  if (BIO_flush(biomemin) != 1)
  {
    rc = MINISECSRV_ERR_BASE64_FLUSHERR;
    goto done;
  }

  /* Read the result from the base64 decoder, until EOF */
  for( ; !BIO_eof(b64) ; )
  {
    tmpsize = BIO_read(b64, buf, sizeof(buf));
    if (tmpsize > 0)
      BIO_write(biomemout, buf, tmpsize);
  }

  *outl = BIO_ctrl_pending(biomemout);
  if (BIO_read(biomemout, out, *outl) != *outl)
  {
    rc = MINISECSRV_ERR_BASE64_CANTREAD;
    goto done;
  }

done:
  BIO_free(b64);
  BIO_free(biomemin);
  BIO_free(biomemout);
  return rc;
}


/******
 * Do the full encrypt job: IV generation, bulk encryption, base64
 * encoding, buffer allocation.
 * The output buffer is allocated for you (set it to NULL at start),
 * it's under your responsibility.
 ******/
int dofullencrypt(minisecsrv_cfg *cfg, unsigned char *in, unsigned int inl, unsigned char **out, unsigned *outl)
{
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char *tmpout = NULL;
  unsigned int tmpoutl;
  int rc = 0;

  /* We need to generate a random IV for each encryption */
  rc = generaterandomiv(cfg, iv);
  if (rc)
    goto done;

  /* Allocate some storage for intermediate result */
  tmpout = malloc(inl+EVP_MAX_BLOCK_LENGTH+EVP_MAX_IV_LENGTH); /* Allocate more for padding and IV */
  if (!tmpout)
  {
    rc = MINISECSRV_ERR_CANTMALLOC;
    goto done;
  }

  /* Write the IV first */
  memcpy(tmpout, iv, cfg->enc->iv_len);

  /* Get the raw encrypted data after the IV */
  rc = dobareencrypt(cfg, iv, in, inl, tmpout+cfg->enc->iv_len, &tmpoutl);
  if (rc)
    goto done;

  /* Adjust the intermediate result size (add IV length) */
  tmpoutl += cfg->enc->iv_len;

  /* And encode the result in base64 */
  *out = malloc(tmpoutl*2); /* TODO: ajuster, *4/3 */
  if (!*out)
  {
    rc = MINISECSRV_ERR_CANTMALLOC;
    goto done;
  }
  rc = dobase64encode(cfg, tmpout, tmpoutl, *out, outl);
  if (rc)
    goto done;

done:
  if (tmpout)
    free(tmpout);
  if (rc && *out)
  {
    free(*out);
    *out = NULL;
  }
  return rc;
}


/******
 * Do the full decrypt job: base64 decoding, IV extraction, bulk
 * decryption, buffer allocation.
 * The output buffer is allocated for you (set it to NULL at start),
 * it's under your responsibility.
 ******/
int dofulldecrypt(minisecsrv_cfg *cfg, unsigned char *in, unsigned int inl, unsigned char **out, unsigned *outl)
{
  unsigned char iv[EVP_MAX_IV_LENGTH];
  unsigned char *tmpout = NULL;
  unsigned int tmpoutl;
  int rc = 0;

  /* Decode the base64 thing */
  tmpout = malloc(inl); /* TODO: ajuster */
  if (!tmpout)
  {
    rc = MINISECSRV_ERR_CANTMALLOC;
    goto done;
  }
  rc = dobase64decode(cfg, in, inl, tmpout, &tmpoutl);
  if (rc)
    goto done;

  if (tmpoutl < cfg->enc->iv_len)
  {
    rc = MINISECSRV_ERR_ENCRYPTEDDATATOOSHORT;
    goto done;
  }

  memcpy(iv, tmpout, cfg->enc->iv_len);

  /* Do a bare decryption */
  *out = malloc(tmpoutl-cfg->enc->iv_len);
  rc = dobaredecrypt(cfg, iv, tmpout+cfg->enc->iv_len, tmpoutl-cfg->enc->iv_len, *out, outl);
  if (rc)
    goto done;

done:
  if (tmpout)
    free(tmpout);
  if (rc && *out)
  {
    free(*out);
    *out = NULL;
  }
  return rc;
}
