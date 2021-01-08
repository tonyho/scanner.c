# scanner.c

[![Build Status](https://travis-ci.com/scanoss/scanner.c.svg?branch=master)](https://travis-ci.com/scanoss/scanner.c)

This is a simple implementation of a console file scanner using the SCANOSS OSSKB, which allows you to perform identification of Open Source components, files or even snippets in your own code. 

For more information, please visit the OSSKB homepage at https://osskb.org

# Pre-requisites

Libcurl must be present in your system.

You can install it with:
```
sudo apt-get install  libcurl-dev
```

# Usage

Scanner requires a file path to be specified as the command argument. If no file is specified, the scanner version and usage help is displayed.

Usage: scanner FILE or scanner DIR

```
Option 			Meaning
-f<format> 		Output format, could be: plain (default), spdx, spdx_xml or cyclonedx
-o<file_name>		Save the scan results in the specified file
-l<file_name> 		Set logs filename
-d			Enable debug messages
-t 			Enable trace messages, enable to see post request to the API
```

Usage example: 

```
$ scanner mz.c
{
  "mz.c": [
    {
      "id": "file",
      "lines": "all",
      "oss_lines": "all",
      "matched": "100%",
      "vendor": "scanoss",
      "component": "minr",
      "version": "1.18",
      "latest": "1.18",
      "url": "https://github.com/scanoss/minr/archive/1.18.tar.gz",
      "file": "minr-1.18/src/mz.c",
      "size": "9680",
      "dependencies": [],
      "licenses": [
        {
          "name": "GPL-2.0-only",
          "source": "declared"
        }
      ],
      "elapsed": "0.000277s"
    }
}
```

# License

scanner.c is released under the GPL 2.0 license. Please check the LICENSE file for further details.
