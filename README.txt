$ git clone https://github.com/jackdoe/cacher
$ cd cacher && go build
$ ./cacher -h
Usage of ./cacher:
 -access="127.0.0.0/8,10.0.0.0/8": allow those networks, use 0.0.0.0/0 to allow everything
 -debug=false: enable/disable debug
 -expire_interval=300: delete expired entries every N seconds
 -listen="[::]:53": listen on (both tcp and udp)
 -max_cache_entries=2000000: max cache entries
 -proxy="8.8.8.8:53,8.8.4.4:53": we proxy requests to those servers
 -timeout=5: timeout

