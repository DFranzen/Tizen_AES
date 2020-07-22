#include <ckmc/ckmc-manager.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int AES_init();

int AES_encrypt_string(char* in, char** out);
int AES_decrypt_string(char* in, char** out);
