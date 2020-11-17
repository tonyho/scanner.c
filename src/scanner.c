// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/scanner.c
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

#define _GNU_SOURCE
#include <ctype.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <dirent.h> 
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "blacklist_ext.h"
#include "external/winnowing.c"

#define VERSION "1.02"
#define API_HOST "osskb.org"
#define API_PORT "443"
#define MAX_HEADER_LEN 1024
#define BUFFER_SIZE 1024
#define MAX_FILE_SIZE (1024 * 1024 * 4)
#define MIN_FILE_SIZE 128

char *wfp_buffer;

bool recursive = false;
char format[10] = "plain";

/* Returns a hexadecimal representation of the first "len" bytes in "bin" */
char *bin_to_hex(uint8_t *bin, uint32_t len)
{
	char digits[] = "0123456789abcdef";
	char *out = malloc(2 * len + 1);
	uint32_t ptr = 0;

	for (uint32_t i = 0; i < len; i++)
	{
		out[ptr++] = digits[(bin[i] & 0xF0) >> 4];
		out[ptr++] = digits[bin[i] & 0x0F];
	}

	out[ptr]=0;
	return out;
}

bool is_dir(char *path)
{
    struct stat pstat;
    if (!stat(path, &pstat)) if (S_ISDIR(pstat.st_mode)) return true;
    return false;
}

bool is_file(char *path)
{
    struct stat pstat;
    if (!stat(path, &pstat)) if (S_ISREG(pstat.st_mode)) return true;
    return false;
}



char *read_file(char *path, long *length)
{
	/* Read file into memory */
	FILE *fp = fopen(path, "rb");
	fseek (fp, 0, SEEK_END);
	*length = ftell (fp);
	char *src = calloc(*length + 1, 1);
	fseek(fp, 0, SEEK_SET);
	fread(src, 1, *length, fp);
	fclose(fp);
	return src;
}

void wfp_capture(char *path)
{
	/* Skip unwanted extensions */
	if (blacklisted(path)) return;

	long length = 0;
	char *src = read_file(path, &length);

	/* Skip if file is under threshold or if content is not wanted*/
	if (length < MIN_FILE_SIZE || unwanted_header(src))
	{
		free(src);
		return;
	}

	/* Calculate MD5 */
	uint8_t bin_md5[16]="\0";
	MD5((uint8_t *) src, length, bin_md5);
	char *hex_md5 = bin_to_hex(bin_md5, 16);

	/* Save file information to buffer */
	sprintf(wfp_buffer + strlen(wfp_buffer), "file=%s,%lu,%s\n", hex_md5, length, path);
	free(hex_md5);

	/* If it is not binary (chr(0) found), calculate snippet wfps */
	if (strlen(src) == length && length < MAX_FILE_SIZE)
	{
		/* Capture hashes (Winnowing) */
		uint32_t *hashes = malloc(MAX_FILE_SIZE);
		uint32_t *lines  = malloc(MAX_FILE_SIZE);
		uint32_t last_line = 0;

		/* Calculate hashes */
		uint32_t size = winnowing(src, hashes, lines, MAX_FILE_SIZE);

		/* Write hashes to buffer */
		for (int i=0; i<size; i++)
		{
			if (last_line != lines[i])
			{
				if (last_line != 0) strcat(wfp_buffer, "\n");
				sprintf(wfp_buffer + strlen(wfp_buffer), "%d=%08x", lines[i], hashes[i]);
				last_line = lines[i];
			}
			else sprintf(wfp_buffer + strlen(wfp_buffer), ",%08x", hashes[i]);
		}
		strcat(wfp_buffer, "\n");

		free(hashes);
		free(lines);
	}
	free(src);
}

bool api_post(BIO *bio,char *format,  char *wfp) {

	char *http_request=calloc(MAX_FILE_SIZE, 1);

	char header_template[] = "POST /api/scan/direct HTTP/1.1\r\n"
			"Host: osskb.org\r\n"
			"Connection: close\r\n"
			"User-Agent: SCANOSS_scanner.c/%s\r\n"
			"Content-Length: %lu\r\n"
			"Accept: */*\r\n"
			"Content-Type: multipart/form-data; boundary=------------------------scanoss_wfp_scan\r\n\r\n";

	char body_template[] = "--------------------------scanoss_wfp_scan\r\n"
        "Content-Disposition: form-data; name=\"format\"\r\n\r\n%s\r\n"
              "--------------------------scanoss_wfp_scan--\r\n"
		"Content-Disposition: form-data; name=\"file\"; filename=\"scan.wfp\"\r\n"
		"Content-Type: application/octet-stream\r\n"
		"\r\n%s\r\n"
		"--------------------------scanoss_wfp_scan--\r\n\r\n";

	/* Assemble request header */
	sprintf(http_request, header_template, VERSION, strlen(body_template) + strlen (format) + strlen (wfp) - 4);

	/* Assemble request body */
	sprintf(http_request + strlen(http_request), body_template,format, wfp);

	/* POST request */
	BIO_write(bio, http_request, strlen(http_request));

	int size;
	char buf[BUFFER_SIZE];
	bool header = true;
	long body_len = 0;
	long body_counter = 0;

	/* Parse response */
	for(;;)
	{
		size = BIO_read(bio, buf, BUFFER_SIZE - 1);
		if(size <= 0) break;
		buf[size] = 0;
		char *body = buf;

		/* Parse response header */
		if (header)
		{
			/* Search for end of header (\r\n\r\n) */
			for (int i = 0; i < (size - 4); i++)
			{
				if (!memcmp(body+i,"\r\n\r\n", 4))
				{
					body = body + i + 4;
					break;
				}
			}
			/* Get body length */
			if (body != buf)
			{
				body_len = strtol(body, &body, 16);
				if (body_len) body += 2;	
				header = false;
			}
			if (header)
			{
				fprintf(stderr, "Error parsing http header:\n%s\n", buf); 
				free(http_request);
				return false;
			}
		}

		body_counter += strlen(body);
		int surplus = body_counter - body_len;
		if (surplus > 0) body[strlen(body)-surplus-2]=0;
		printf(body);
	}

	free(http_request);
	return true;
}

/* Scan a file */
bool file_proc(char * path)
{
	wfp_buffer = calloc(MAX_FILE_SIZE, 1);
	*wfp_buffer = 0;
	wfp_capture(path);

	if (*wfp_buffer)
	{
	    BIO* bio;
		SSL_CTX* ctx;

		/* Establish SSL connection */
		SSL_library_init();
		ctx = SSL_CTX_new(SSLv23_client_method());
		if (ctx == NULL) return false;
    	bio = BIO_new_ssl_connect(ctx);
		BIO_set_conn_hostname(bio, API_HOST ":" API_PORT);

		if(BIO_do_connect(bio) <= 0) return false;
		api_post(bio,format, wfp_buffer);

		/* Free SSL connection */
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
	}
	free(wfp_buffer);
    return true;
}

/* Scan all files from a Directory*/
bool dir_proc(char * path)
{
  DIR * d = opendir(path); 
  if(d==NULL) return false; 
  struct dirent * entry; // for the directory entries
  
  while ((entry = readdir(d)) != NULL)
  {
        char temp[strlen(path) + strlen(entry->d_name)+1];
        
        sprintf(temp,"%s/%s",path,entry->d_name);
  
        if(is_dir(temp) && (recursive) && //recurvise mode
        !((strlen(entry->d_name) == 1 && entry->d_name[0] == '.') || (strlen(entry->d_name) == 2 && entry->d_name[1] == '.'))) //avoid roots
        {
            dir_proc(temp); 
        }
        else if (is_file(temp))
        {
            fprintf(stderr, "\n%s ",temp);
            file_proc(temp);
        }
    }
    
    closedir(d); 
    return true;
}


int main(int argc, char *argv[])
{
    int param = 0;
    
    /* Command parser */
    while ((param = getopt (argc, argv, "hrf:")) != -1)
        switch (param)
        {
        case 'r':
            recursive = true; //recursive mode
            break;
        case 'f':
            if (strstr(optarg,"plain") || strstr(optarg,"spdx") || strstr(optarg,"cyclonedx"))
                strncpy(format,optarg,sizeof(format));
            else
                fprintf(stderr, "%s is not a valid output format, using plain\n",optarg);
            break;
        case 'h':
        default:
            fprintf(stderr, "SCANOSS scanner-%s\n", VERSION);
            fprintf(stderr, "Usage: scanner FILE or scanner DIR\n");
            fprintf(stderr, "Option\t\t Meaning\n");
            fprintf(stderr, "-h\t\t Show this help\n");
            fprintf(stderr, "-f<format>\t Output format, could be: plain (default), spdx or cyclonedx.\n");
            fprintf(stderr, "-r\t\t Recursive mode, use with DIR\n");
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
        if (!recursive)
        {
            fprintf(stderr,"%s is a directory, scan all files? y/n\n",path);
            if (getchar()!='y') return EXIT_SUCCESS;
        }
        
        dir_proc(path);
    }
    else
    {
        fprintf(stderr,"%s is not a file\n", path);
        return EXIT_FAILURE;
    }
	
	return EXIT_SUCCESS;
}
