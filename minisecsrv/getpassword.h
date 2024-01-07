#ifndef MINISECSRV_GETPASSWORD_H
#define MINISECSRV_GETPASSWORD_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>

/**
 * \brief Read a password without character echoing.
 * \note Input ends only when an EOF or LF character is encountered.
 * \param prompt Password prompt, if NULL "Passphrase: " is used. If empty ("")
 * no prompt is used.
 * \param buffer Somewhere to store the password. This will be made larger if
 * necessary, although the enlargening operation will be slow. If NULL, the function fails.
 * \param replacement Character to print instead of printing input characters.
 * If this is '\0'; none is used.
 * \return 0 on success or -1 on error.
 */
int getpassword(const char* prompt, char** buffer, int* sz, char replacement);

#endif
