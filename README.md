About
=====
An NGINX Module for SEO. It searches for the </head> tags and injects data fetched from the memcached for a particluar request on the fly.

Memcache key format  for a request: 'md5(http + $Host + $URI)'.


Status
======
This module is production-ready and it's compatible with nginx 1.11.3 or later


Configuration directives
========================
boron_memcached_config
----------------
* **syntax**: `boron_memcached_config "--SERVER=localhost:11211";`
* **default**: `none`
* **context**: `server`

Defines memcached configuration.


boron filter
------------
* **syntax**: `boron on | off;`
* **default**: `off`
* **context**: `http`, `server`, `location`

Enable or disable the boron filter.
  

boron_once
----------------
* **syntax**: `boron_once on | off;`
* **default**: `boron_once on;`
* **context**: `http`, `server`, `location`

Indicates whether to replace tag with memcached data once or repeatedly at multiple locations.


boron_last_modified
------------------
* **syntax**: `boron_last_modified on | off;`
* **default**: `boron_last_modified off;`
* **context**: `http, server, location`

Allows preserving the “Last-Modified” header field from the original response during replacement to facilitate response caching.

By default, the header field is removed as contents of the response are modified during processing.


boron_types
-----------------
* **syntax**: `boron_types mime-type ...;`
* **default**: `boron_types text/html;`
* **context**: `http, server, location`

Enables string replacement in responses with the specified MIME types in addition to “text/html”. The special value “*” matches any MIME type (0.8.29).


Sample configuration
====================
    http {

        error_log /var/log/nginx/error.log debug;

        server {

            boron_memcached_config "--SERVER=localhost:11211";

            location / {
            proxy_pass   http://localhost:8000;
            boron on;
            boron_once on;
            }
       }
    }


Installation
============

You need to install the libmemcached first.

Obtain NGIXN Source:

```bash
    #  wget http://nginx.org/download/nginx-1.11.3.tar.gz
    #  tar xvf nginx-1.11.3.tar.gz
    #  cd nginx-1.11.3.tar.gz
```

And then rebuild NGINX:

```bash
    # ./configure --add-module=/path/to/ngx_http_boron_filter_module --with-debug
    # make
    # make install
```


Debug
======

Configure NGINX in debug mode by adding before performing make: 

```bash
    # ./configure --with-debug ...
```

Add `error_log /var/log/nginx/error.log debug;` inside http context in nginx.conf.

Check `boron` logs:

```bash
    # tail -f /var/log/nginx/error.log | grep boron
```
 
Author
======

Gurmohit Singh

See Also
========

* The standard ngx_sub_filter module: http://nginx.org/en/docs/http/ngx_http_sub_module.html
