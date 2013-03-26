static char rcsid[] = "$Id: config.c,v 1.1 2013/03/26 23:32:31 eabalea Exp $";

/**************
 * Necessary include files
 **************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <dirent.h>
#include <openssl/evp.h>
#include "utils.h"
#include "config.h"

#define STRCMP(a, b) strncasecmp(a, b, strlen(b))

/******
 * void readrcfile(void)
 *
 * This function must read the specified rc file, and set the corresponding
 * data structures in memory
 ******/
void readrcfile(minisecsrv_cfg *cfg)
{
  FILE *f;
  unsigned char rcfile[MAXNAMLEN+1];
  unsigned char buf[1024];
  unsigned char dummystr[1024];
  
  memset(rcfile, sizeof(rcfile), 0);
  strncpy(rcfile, cfg->rcfile, sizeof(rcfile)-1);
  expandfilename(rcfile);
  
  /* Let's try to open it */
  f = fopen(rcfile, "rt");
  if (!f)
  {
    fprintf(stderr, "Unable to open resource file: %s\n", rcfile);
    exit(-1);
  }
  
  /* And parse it one line at a time */
  while(!feof(f))
  {
    buf[0] = 0;
    fgets(buf, sizeof(buf)-1, f);
    trim(buf);
    switch (buf[0])
    {
      /* Ignore all the comment and empty lines */
      case '#': break;
      case ';': break;
      case 0  : break;

      /* Now we've got something interesting to read */
      default : 
	if (!STRCMP(buf, "Cipher"))
	{
	  cfg->cipher = strdup(buf+strlen("Cipher"));
	  trim(cfg->cipher);
	  break;
	}

	if (!STRCMP(buf, "PBKDF2Hash"))
	{
	  cfg->hash = strdup(buf+strlen("PBKDF2Hash"));
	  trim(cfg->hash);
	  break;
	}

	if (!STRCMP(buf, "PBKDF2Iterations"))
	{
	  cfg->iterations = integervalue(buf+strlen("PBKDF2Iterations"));
	  break;
	}

	if (!STRCMP(buf, "PBKDF2Salt"))
	{
	  cfg->salt = strdup(buf+strlen("PBKDF2Salt"));
	  trim(cfg->salt);
	  break;
	}

	if (!STRCMP(buf, "Port"))
	{
	  cfg->port = integervalue(buf+strlen("Port"));
	  break;
	}

        if (!STRCMP(buf, "Output"))
        {
	  memset(dummystr, sizeof(dummystr), 0);
          strncpy(dummystr, buf+strlen("Output"), sizeof(dummystr)-1);
          trim(dummystr);
          expandfilename(dummystr);
	  cfg->output = strdup(dummystr);
          break;
        }
        
        if (!STRCMP(buf, "EnableOutput"))
        {
          cfg->enableoutput = booleanvalue(buf+strlen("EnableOutput"));
          break;
        }
        
        /* None of the above, just issue a warning */
        fprintf(stderr, "Warning, line '%s' ignored.\n", buf);
        break;
    }
  }
  fclose(f);
}


void checkconfig(minisecsrv_cfg *cfg)
{
  cfg->enc = EVP_get_cipherbyname(cfg->cipher);
  if (!cfg->enc)
  {
    printf("Cipher %s unknown.\n", cfg->cipher);
    exit(-1);
  }

  if ((cfg->port > 65535) || (cfg->port < 1))
  {
    printf("Port %d invalid, using default %d.\n", cfg->port, MINISECSRV_DEFAULTPORT);
    cfg->port = MINISECSRV_DEFAULTPORT;
  }

  cfg->digest = EVP_get_digestbyname(cfg->hash);
  if (!cfg->digest)
  {
    printf("Digest %s unknown.\n", cfg->hash);
    exit(-1);
  }

  if (cfg->iterations < 1)
  {
    printf("Iterations set to unsafe value %d, using default %d.\n", cfg->iterations, MINISECSRV_DEFAULTITERATIONS);
    cfg->iterations = MINISECSRV_DEFAULTITERATIONS;
  }
}


/******
 * void init(int argc, char **argv)
 *
 * We start by reading the rc file, and populate the necessary tables
 * in memory
 ******/
void init(int argc, char **argv, minisecsrv_cfg **maincfg)
{
  int c;
  int digit_optind = 0;
  minisecsrv_cfg *cfg;

  cfg = malloc(sizeof(minisecsrv_cfg));
  *maincfg = cfg;
  memset(cfg, sizeof(*cfg), 0);
  cfg->rcfile = strdup(MINISECSRV_DEFAULTRCFILE);
  cfg->port = MINISECSRV_DEFAULTPORT;
  cfg->cipher = strdup(MINISECSRV_DEFAULTCIPHER);
  cfg->iterations = MINISECSRV_DEFAULTITERATIONS;
  cfg->hash = MINISECSRV_DEFAULTHASH;
  cfg->passphrase = "toto";

  OpenSSL_add_all_algorithms();
  /* TODO: mettre en place les handlers pour mutex */

  while (1) {
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    static struct option long_options[] = {
      { "config", 1, 0, 'c' },
      { "debug", 0, 0, 'd' },
      { "printcheck", 0, 0, 'a' },
      { "help", 0, 0, 'h' },
      { 0, 0, 0, 0 }
    };

    c = getopt_long (argc, argv, "c:phd",
	long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
      case 'c':
	if (cfg->rcfile)
	  free(cfg->rcfile);
	cfg->rcfile = strdup(optarg);
	break;

      case 'h':
	printhelp();
	break;

      case 'd':
	cfg->debug = 1;
	break;

      case 'p':
	cfg->printcheck = 1;

      case '?':
	break;

      default:
	printf ("?? getopt returned character code 0%o ??\n", c);
    }
  }

  if (optind < argc) {
    printf ("non-option ARGV-elements: ");
    while (optind < argc)
      printf ("%s ", argv[optind++]);
    printf ("\n");
  }

  readrcfile(cfg);
  checkconfig(cfg);

  /* TODO: ask for the passphrase and init crypto elements */
  cfg->key = malloc(cfg->enc->key_len);
  PKCS5_PBKDF2_HMAC(cfg->passphrase, strlen(cfg->passphrase), cfg->salt, strlen(cfg->salt), cfg->iterations, cfg->digest, cfg->enc->key_len, cfg->key);

  if (cfg->printcheck)
  {
    /* TODO: afficher de quoi vérifier la passphrase, comme par
     * exemple le chiffré d'un bloc de 0
     */
  }
}

