#ifndef __SCANNNER_H
#define __SCANNER_H

#include <stdbool.h>

#define VERSION "1.1.2"
#define MAX_HEADER_LEN 1048576
#define BUFFER_SIZE_MAX 524288
#define BUFFER_SIZE_MIN 256
#define BUFFER_SIZE_DEFAULT 524288
#define MAX_FILE_SIZE (1024 * 1024 * 4)
#define MIN_FILE_SIZE 128


void scanner_set_log_level(int level);
void scanner_set_verbose(bool in);
void scanner_set_buffer_size(unsigned int size);
void scanner_set_format(char * form);
void scanner_set_host(char * host);
void scanner_set_port(char * port);

bool scanner_is_dir(char *path);
bool scanner_is_file(char *path);

bool scanner_dir_proc(char * path, FILE * output);
bool scanner_file_proc(char * path, FILE * output);

bool scanner_scan(char * host, char * port, char * session, char * format, char * path, char * file);


#endif
