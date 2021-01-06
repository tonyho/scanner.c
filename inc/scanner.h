// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/scanner.h
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



#ifndef __SCANNNER_H
#define __SCANNER_H

#include <stdbool.h>

#define VERSION "1.1.3"
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

bool scanner_recursive_scan(char * path, FILE * output);
bool scanner_scan(char * host, char * port, char * session, char * format, char * path, char * file);


#endif
