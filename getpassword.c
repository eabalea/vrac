#include "getpassword.h"

/**
 * \brief Read a password without character echoing.
 * \note Input ends only when an EOF or LF character is encountered.
 * \param prompt Password prompt, if NULL "Password: " is used. If empty ("")
 * no prompt is used.
 * \param buffer Somewhere to store the password. This will be made larger if
 * necessary, although the enlargening operation will be slow. If NULL, the function fails.
 * \param replacement Character to print instead of printing input characters.
 * If this is '\0'; none is used.
 * \return 0 on success or -1 on error.
 */
int getpassword(const char* prompt, unsigned char** buffer, unsigned int* sz, char replacement)
{
  const char* default_prompt = "Passphrase: ";
  struct termios tty_attr;
  tcflag_t c_lflag;
  int i = 0,
      c = 0;
  int rc = 0;

  if (!buffer)
  {
    rc = -1;
    goto done;
  }

  /*
   * Decide what prompt to print, if any, and then print it
   */
  if (prompt != NULL)
    fprintf(stderr, "%s", prompt);
  else if (prompt != "")
    fprintf(stderr, "%s", default_prompt);
	
  /*
   * Disable character echoing and line buffering
   */	
  if (tcgetattr(STDIN_FILENO, &tty_attr) < 0)
  {
    rc = -1;
    goto done;
  }

  c_lflag = tty_attr.c_lflag; /* Allows us to restore this later */
  tty_attr.c_lflag &= ~ICANON;
  tty_attr.c_lflag &= ~ECHO;

  if (tcsetattr(STDIN_FILENO, 0, &tty_attr) < 0)
  {
    rc = -1;
    goto done;
  }
	
  for (; (c = getchar()) != '\n' && c != EOF; ++i) {
    /*
     * If the buffer gets too full, expand it
     */
    if (i > *sz) {
      if (!realloc(*buffer, (*sz)+1))
      {
	rc = -1;
	goto done;
      }
      (*sz) += 1;
    }
    
    if (replacement)
      putchar(replacement);
		
    (*buffer)[i] = c;
  }
	
  if (replacement)
    putchar('\n');

  /* Append a NUL byte, expand the buffer if necessary */
  if (i > *sz)
  {
    if (!realloc(*buffer, (*sz)+1))
    {
      rc = -1;
      goto done;
    }
    (*sz) += 1;
  }
  (*buffer)[i] = 0;

  /* 
   * Re-enable character echoing and line buffering
   */
  tty_attr.c_lflag = c_lflag;

  if (tcsetattr(STDIN_FILENO, 0, &tty_attr) < 0)
  {
    rc = -1;
    goto done;
  }

done:
  return rc;
}

