
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/ 
/* <DESC>
 * Issue an HTTP POST and provide the data through the read callback.
 * </DESC>
 */ 
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <stdlib.h>
#include "api_post.h"
#include "log.h" 

struct WriteThis {
  const char *readptr;
  size_t sizeleft;
};
 
static size_t read_callback(char *dest, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *wt = (struct WriteThis *)userp;
  size_t buffer_size = size*nmemb;
 
  if(wt->sizeleft) {
	/* copy as much as possible from the source to the destination */ 
	size_t copy_this_much = wt->sizeleft;
	if(copy_this_much > buffer_size)
	  copy_this_much = buffer_size;
	memcpy(dest, wt->readptr, copy_this_much);
    log_debug(wt->readptr);
	wt->readptr += copy_this_much;
	wt->sizeleft -= copy_this_much;
	return copy_this_much; /* we copied this many bytes */ 
  }
 
  return 0; /* no more data left to deliver */ 
}
 
int api_curl_post(char * host, char * session, char *format, char *wfp)
{
    
    char content_len[] = "Content-Length: %lu";
   char body_template[] = "--------------------------scanoss_wfp_scan\r\n"
        "Content-Disposition: form-data; name=\"format\"\r\n\r\n%s\r\n"
              "--------------------------scanoss_wfp_scan--\r\n"
		"Content-Disposition: form-data; name=\"file\"; filename=\"scan.wfp\"\r\n"
		"Content-Type: application/octet-stream\r\n"
		"\r\n%s\r\n"
		"--------------------------scanoss_wfp_scan--\r\n\r\n";
    
	char *http_request=calloc(1024*1024, 1);
    sprintf(http_request,body_template,format,wfp);
    
    log_debug(http_request);
    
    CURL *curl;
    CURLcode res;
    
    struct WriteThis wt;
    struct curl_httppost* post = NULL;
    struct curl_httppost* last = NULL;
  wt.readptr = http_request;
  wt.sizeleft = strlen(http_request);
  
  sprintf(content_len,content_len,wt.sizeleft);
 
  /* In windows, this will init the winsock stuff */ 
  res = curl_global_init(CURL_GLOBAL_DEFAULT);
  /* Check for errors */ 
  if(res != CURLE_OK) {
	fprintf(stderr, "curl_global_init() failed: %s\n",
			curl_easy_strerror(res));
	return 1;
  }
 
  /* get a curl handle */ 
  curl = curl_easy_init();
  if(curl) {
	/* First set the URL that is about to receive our POST. */ 
	curl_easy_setopt(curl, CURLOPT_URL, host);
    curl_easy_setopt(curl, CURLOPT_PORT, 443L);
	/* Now specify we want to POST data */ 
	//curl_easy_setopt(curl, CURLOPT_POST, 1L);
 
	/* we want to use our own read function */ 
	//curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, http_request);
 
    /* set the size of the postfields data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, wt.sizeleft);
	/* pointer to pass to our read function */ 
	curl_easy_setopt(curl, CURLOPT_READDATA, 893);
 
	/* get verbose debug output please */ 
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    
        struct curl_slist *chunk = NULL;
        chunk = curl_slist_append(chunk, "Connection: close");
        chunk = curl_slist_append(chunk, "User-Agent: SCANOSS_scanner.c/1.1.2");
        chunk = curl_slist_append(chunk, content_len);
        chunk = curl_slist_append(chunk, "Transfer-Encoding: chunked");
        chunk = curl_slist_append(chunk, "Content-Type: multipart/form-data; boundary=------------------------scanoss_wfp_scan");
        chunk = curl_slist_append(chunk, "Expect:");
        res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	  /* use curl_slist_free_all() after the *perform() call to free this
		 list again */ 
 
 
	/* Perform the request, res will get the return code */ 
	res = curl_easy_perform(curl);
	/* Check for errors */ 
	if(res != CURLE_OK)
	  fprintf(stderr, "curl_easy_perform() failed: %s\n",
			  curl_easy_strerror(res));
 
	/* always cleanup */ 
	curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return 0;
}

