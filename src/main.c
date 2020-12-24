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

#include "scanner.h"

int main(int argc, char *argv[])
{
    int param = 0;
    
    /* Command parser */
    while ((param = getopt (argc, argv, "f:b:hv")) != -1)
        switch (param)
        {
        case 'b': //set http response buffe size
            buffer_size = atoi(optarg);
            if (buffer_size > BUFFER_SIZE_MAX || buffer_size < BUFFER_SIZE_MIN )
            {
                buffer_size = BUFFER_SIZE_DEFAULT;
                fprintf(stderr,"Wrong buffer size, using default: %d",buffer_size);
            }
            
            break;
        case 'v':
            verbose = true;
             fprintf(stderr, "verbose mode\n");
            break;
        case 'f':
            if (strstr(optarg,"plain") || strstr(optarg,"spdx") || strstr(optarg,"cyclonedx"))
                strncpy(format,optarg,sizeof(format));
            else
                fprintf(stderr, "%s is not a valid output format, using plain\n",optarg);
                
            if (verbose) fprintf(stderr, "Selected format: %s\n",format);
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
    
    if (is_file(path))
    {
        file_proc(path);
    }
    else if (is_dir(path)) 
    {
        int path_len = strlen(path);
        if (path_len > 1 && path[path_len-1] == '/') //remove extra /
            path[path_len-1] = '\0';
        
        dir_proc(path);
    }
    else
    {
        fprintf(stderr,"%s is not a file\n", path);
        return EXIT_FAILURE;
    }
	
	return EXIT_SUCCESS;
}
