// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/main.c
 *
 * A simple SCANOSS client in C for direct file scanning
 *
 * Copyright (C) 2018-2020 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h> 
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#include "scanner.h"

int main(int argc, char *argv[])
{
    int param = 0;
    FILE * output = NULL;
    /* Command parser */
    while ((param = getopt (argc, argv, "H:p:f:b:o:hvd")) != -1)
        switch (param)
        {
            case 'H':
                scanner_set_host(optarg);
                break;
            case 'p':
                scanner_set_port(optarg);
                break;
            case 'b': //set http response buffe size
            {
                unsigned int buffer_size = atoi(optarg);
                scanner_set_buffer_size(buffer_size);
                break;
            }
            case 'v':
                scanner_set_verbose(true);
                fprintf(stderr, "verbose mode\n");
                break;
            case 'f':
                scanner_set_format(optarg);
                break;
            case 'o':
                output = fopen(optarg,"w+");
                break;
            case 'd':
                scanner_set_log_level(1);
                break;
            case 'h':
            default:
                fprintf(stderr, "SCANOSS scanner-%s\n", VERSION);
                fprintf(stderr, "Usage: scanner FILE or scanner DIR\n");
                fprintf(stderr, "Option\t\t Meaning\n");
                fprintf(stderr, "-h\t\t Show this help\n");
                fprintf(stderr, "-f<format>\t Output format, could be: plain (default), spdx, spdx_xml or cyclonedx.\n");
                fprintf(stderr, "-b<bytes>\t HTTP response buffer size, default: %d bytes\n",BUFFER_SIZE_DEFAULT);
                fprintf(stderr, "-v\t\t Enable verbosity (via STDERR)\n");
                fprintf(stderr, "\nFor more information, please visit https://scanoss.com\n");
                exit(EXIT_FAILURE);
            break;
        }
    
       
    char *path = argv[optind];
    
    if (!output)
        output = stdout;
        
    if (scanner_is_file(path))
    {
        scanner_file_proc(path, output);
    }
    else if (scanner_is_dir(path)) 
    {
        int path_len = strlen(path);
        
        if (path_len > 1 && path[path_len-1] == '/') //remove extra /
            path[path_len-1] = '\0';
        
        fprintf(output,"[");
        scanner_dir_proc(path,output);
        fseek(output, -1L, SEEK_CUR);
       // ungetc(']', output); 
        fprintf(output,"]");
    }
    else
    {
        fprintf(stderr,"%s is not a file\n", path);
        return EXIT_FAILURE;
    }
	
     fclose(output);

    
	return EXIT_SUCCESS;
}
