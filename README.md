# ngx_http_upstream_cache_vars_module

# Name
ngx_http_upstream_cache_vars_module is a nginx module to provide a collection of upstream cache metadata variables.

# Table of Content

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Installation](#installation)
* [Varaibles](#variables)
* [Author](#author)
* [License](#license)

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

This module cannot be used with freenginx due to variable name conflicts. If you really need to use it with freenginx, you can first remove the variables $upstream_cache_age and $upstream_cache_key from this module code.

# Synopsis

```nginx
http {
    proxy_cache_path /data/nginx/cache levels=1:2 keys_zone=one:10m;
    proxy_cache one;
    proxy_cache_valid 200 206 30s;

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location / {
            add_header Age $upstream_cache_age;
            proxy_pass http://foo.com;
        }
    }
}
```

# Installation

To use theses modules, configure your nginx branch with `--add-module=/path/to/ngx_http_upstream_cache_vars_module`.

# Variables

## \$upstream_cache_key

the cache key being used.

## \$upstream_cache_key_crc32

the crc32 checksum of cache key.

## \$upstream_cache_key_hash

the md5sum hash of cache key.

## \$upstream_cache_main_hash

the md5sum hash of main cache key.

## \$upstream_cache_variant_hash

the md5sum hash of variant cache key when a request is cached based on the Vary response header.

## \$upstream_cache_file

the file path of upstream cache.

## \$upstream_cache_age

age of the cache item.

## \$upstream_cache_create_time

cache create time. unix time.

## \$upstream_cache_create_date

cache create time. the time format is consistent with the http `Date` header.

## \$upstream_cache_expire_time

cache expire time. unix time.

## \$upstream_cache_expire_date

cache expire time. the time format is consistent with the http `Date` header.

## \$upstream_cache_ttl

cache ttl.

## \$upstream_cache_max_age

cache max age.

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
