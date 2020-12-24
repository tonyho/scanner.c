#ifndef __SCANNNER_H
#define __SCANNER_H

#include <stdbool.h>

#define VERSION "1.1.1"
#define API_HOST "osskb.org"
#define API_PORT "443"
#define MAX_HEADER_LEN 1048576
#define BUFFER_SIZE_MAX 524288
#define BUFFER_SIZE_MIN 256
#define BUFFER_SIZE_DEFAULT 524288
#define MAX_FILE_SIZE (1024 * 1024 * 4)
#define MIN_FILE_SIZE 128


extern unsigned int buffer_size;
extern char format[10];
extern bool verbose;

bool is_dir(char *path);
bool is_file(char *path);
bool dir_proc(char * path);
bool file_proc(char * path);





#endif
