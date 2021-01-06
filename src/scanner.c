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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>


#include "scanner.h"
#include "blacklist_ext.h"
#include "winnowing.h"
#include "api_post.h"
#include "log.h"
//#define DEBUG /* uncomment this define to enable some debug outputs */

/*SCANNER PRIVATE PROPERTIES*/
#define API_HOST_DEFAULT "osskb.org"
#define API_PORT_DEFAULT "443"
#define API_SESSION_DEFAULT "\0"

static char API_host[32] = API_HOST_DEFAULT;
static char API_port[5] = API_PORT_DEFAULT;
static char API_session[33] = API_SESSION_DEFAULT;

static unsigned int buffer_size = BUFFER_SIZE_DEFAULT;
static char format[10] = "plain";
static unsigned int proc_files = 0;

/* Returns a hexadecimal representation of the first "len" bytes in "bin" */
static char *bin_to_hex(uint8_t *bin, uint32_t len)
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

static char *read_file(char *path, long *length)
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

static void report_open(FILE * output)
{
    if (strstr(format,"plain"))
    {
        fprintf(output,"{");
    }
    else if (strstr(format,"xml"))
    {
        fprintf(output,"<root>");
    } 
    else if (strstr(format,"spdx"))
    {
        fprintf(output,"[");
    }
}

static void report_close(FILE * output)
{
    if (output == stdout)
        fprintf(output,"\b");
    else
        fseek(output,-1L,SEEK_CUR);
        
    if (strstr(format,"plain"))
    {
        fprintf(output,"}");
    }
     else if (strstr(format,"xml"))
    {
        fprintf(output,"\n</root>");
    } 
    else if (strstr(format,"spdx"))
    {
        fprintf(output,"]");
    }
}

static void report_separator(FILE * output)
{
    if (!strstr(format,"xml"))
    {
        fprintf(output,",");
    }
}
        

static void wfp_capture(char *path, char *wfp_buffer)
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

static bool api_post(BIO *bio,char * host, char * session, char *format,  char *wfp, FILE * output) {

	char *http_request=calloc(MAX_FILE_SIZE, 1);

	char header_template[] = "POST /api/scan/direct HTTP/1.1\r\n"
			"Host: %s\r\n"
            "X-session: %s\r\n"
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
	sprintf(http_request, header_template, host,session, VERSION, strlen(body_template) + strlen (format) + strlen (wfp) - 4);
	/* Assemble request body */
	sprintf(http_request + strlen(http_request), body_template,format, wfp);

	/* POST request */
	BIO_write(bio, http_request, strlen(http_request));
    
    /*This symbols are used to parse the api response in buf, at this moment it could be a JSON or XML format */
    char symbol_start = '{'; 
    char symbol_stop = '}';
	int size;
    bool state = true;
	bool header = true;
	int body_len = 0;
    char * body_start;
    char * body_end;
    int block_read = 0;
    char * buf = malloc(sizeof(char)*buffer_size+1);
    
     /* Parse response */
    do
    {
        memset(buf,'\0',buffer_size);
        size = BIO_read(bio, buf, buffer_size);

        log_trace("\n---- api post buffer start ----\n");
        log_trace(buf);
        log_trace("\n---- api post buffer end ----\n");

        if (strstr(format,"xml")) //adjust parsing for xml implementation
        {
            symbol_start = '<';
            symbol_stop = '>';
        }
        
        if (size)
        {
            if (header && strstr(buf,"HTTP")) //find the header
            {
                body_start = strchr(buf,symbol_start); //find the JSON start
                body_len = strtol(body_start-5, &body_start, 16); //cast body lenght
                header = false;
                body_end = strrchr(buf,symbol_stop);// find the last }

                if (body_end-body_start >= body_len-2) //Its complete
                {
                    if (strstr(format,"plain")) //remove fist and last brackets (recursive plain format fix)
                    {
                        body_start += 3;
                        body_end -= 2;
                    }
                   block_read += fprintf(output,"%.*s\n", body_end - body_start+1, body_start); 
                   state = false;
                   break;
                }
                else
                {
                    log_error("Buffer overflow, please increase the buffer using -b option");
                }
            }
            
        }
        
    } while (size > 0 && block_read <= body_len-2);

	free(http_request);
    free(buf);
	return state;
}


static bool scanner_is_dir(char *path)
{
    struct stat pstat;
    if (!stat(path, &pstat)) if (S_ISDIR(pstat.st_mode)) return true;
    return false;
}

static bool scanner_is_file(char *path)
{
    struct stat pstat;
    if (!stat(path, &pstat)) if (S_ISREG(pstat.st_mode)) return true;
    return false;
}

/* Scan a file */
static bool scanner_file_proc(char * path, FILE * output)
{
	bool state = true;
    char * wfp_buffer = calloc(MAX_FILE_SIZE, 1);
	
    *wfp_buffer = 0;
	
    wfp_capture(path, wfp_buffer);

	if (*wfp_buffer)
	{
	    BIO* bio;
		SSL_CTX* ctx;
        
        log_debug("BIO_do_connect to: %s:%s", API_host, API_port);
        
        /* Establish SSL connection */
		
        SSL_library_init();
		
        ctx = SSL_CTX_new(SSLv23_client_method());
		
        if (ctx == NULL) return false;
    	bio = BIO_new_ssl_connect(ctx);
		
        BIO_set_conn_hostname(bio,API_host);
        BIO_set_conn_port(bio,API_port);

		if (BIO_do_connect(bio) <= 0)
        {    
            log_error("Connetion fails: %s:%s", API_host, API_port);
            return false;
        }
              
		api_post(bio,API_host,API_session, format, wfp_buffer, output);

		
        /* Free SSL connection */
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
        
        state = false;
    }

	free(wfp_buffer);
    return state;
}

/* Scan all files from a Directory*/
static bool scanner_dir_proc(char * path, FILE * output)
{
  
  bool state = true; //true if were a error  
  DIR * d = opendir(path); 
  if(d==NULL) return false; 
  struct dirent * entry; // for the directory entries
  
  while ((entry = readdir(d)) != NULL)
  {
        char temp[strlen(path) + strlen(entry->d_name)+1];
        
        sprintf(temp,"%s/%s",path,entry->d_name);
  
        if(scanner_is_dir(temp) &&
        !((strlen(entry->d_name) == 1 && entry->d_name[0] == '.') || (strlen(entry->d_name) == 2 && entry->d_name[1] == '.'))) //avoid roots
        {
            scanner_dir_proc(temp, output); 
        }
        else if (scanner_is_file(temp))
        {
            if (!scanner_file_proc(temp, output))
            {
                report_separator(output);
                
                proc_files++;
                
                if (output != stdout)
                    log_info("Processed files: %d",proc_files);
            }
            state = false;
        }
    }
    
    closedir(d); 
    return state;
}



/********* PUBLIC FUNTIONS DEFINITION ************/

void scanner_set_buffer_size(unsigned int size)
{
    if (size > BUFFER_SIZE_MAX || size < BUFFER_SIZE_MIN )
    {
        buffer_size = BUFFER_SIZE_DEFAULT;
        log_info("Wrong buffer size, using default: %d",buffer_size);
    }
}

void scanner_set_format(char * form)
{
    if (strstr(form,"plain") || strstr(form,"spdx") || strstr(form,"cyclonedx"))
        strncpy(format,form,sizeof(format));
    else
       log_info("%s is not a valid output format, using plain\n",form);
    
}

void scanner_set_host(char * host)
{
    memset(API_host,'\0',sizeof(API_host));
    strncpy(API_host,host,sizeof(API_host));
    log_debug("Host set: %s",API_host);
}

void scanner_set_port(char * port)
{
    memset(API_port,'\0',sizeof(API_port));
    strncpy(API_port,port,sizeof(API_port));
    log_debug("Port set: %s",API_port);
}

void scanner_set_session(char * session)
{
    memset(API_session,'\0',sizeof(API_session));
    strncpy(API_session,session,sizeof(API_session));
    log_debug("Session set: %s",API_session);
}

void scanner_set_log_level(int level)
{
    log_set_level(level);
}

bool scanner_recursive_scan(char * path, FILE * output)
{
    bool state = true;
    log_debug("Scan start");
    proc_files = 0;
    
    report_open(output);    
    
    if (scanner_is_file(path))
    {
        scanner_file_proc(path, output);
        state = false;
    }
    else if (scanner_is_dir(path)) 
    {
        int path_len = strlen(path);
        if (path_len > 1 && path[path_len-1] == '/') //remove extra '/'
            path[path_len-1] = '\0';
        
        scanner_dir_proc(path, output);
        state = false;
    }
    else
    {
        log_error(stderr,"\"%s\" is not a file\n", path);
    }
    
    report_close(output);
    
    if (output)
        fclose(output);
        
    return state;
}

bool scanner_scan(char * host, char * port, char * session, char * format, char * path, char * file)
{
    FILE * output;
    
    if (file != NULL)
    {
        output = fopen(file,"w+");
        log_debug("File open: %s",file);
    }
    
    scanner_set_host(host);
    scanner_set_port(port);
    scanner_set_session(session);
    scanner_set_format(format);
    
    return scanner_recursive_scan(path,output);
	
}