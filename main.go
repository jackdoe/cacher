package main

import (
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

var DEBUG bool

type CacheEntry struct {
	expire_at int64
	message   dns.Msg
}

type Proxy struct {
	CACHE       map[string]*CacheEntry
	ACCESS      []*net.IPNet
	SERVERS     []string
	s_len       int
	entries     int64
	max_entries int64
	NOW         int64
	giant       *sync.RWMutex
	timeout     time.Duration
}

func (this Proxy) expire_cache() {
	expired := 0
	this.entries = 0
	this.giant.Lock()
	defer this.giant.Unlock()
	for k, v := range this.CACHE {
		if this.NOW > v.expire_at {
			delete(this.CACHE, k)
			expired += 1
		} else {
			this.entries += 1
		}
	}
	_D("expired %d entries, total: %d", expired, this.entries)
}
func (this Proxy) get_cache_key(req *dns.Msg) string {
	key := ""
	for _, q := range req.Question {
		key = fmt.Sprintf("%s_%d_%d_%s", key, q.Qtype, q.Qclass, q.Name)
	}
	return key
}
func (this Proxy) cache_set(req *dns.Msg, value *dns.Msg) {
	this.giant.Lock()
	defer this.giant.Unlock()

	key := this.get_cache_key(req)
	if this.entries < this.max_entries && key != "" {
		expire := int64(144000)
		for _, rr := range value.Answer {
			ttl := int64(rr.Header().Ttl)
			if ttl < expire {
				expire = ttl
			}
		}
		_D("STORE: caching %s for %d seconds\n", key, expire)
		//_D("REQUEST:%sCACHED:%s", expire, prettify_request(req), prettify_request(value))
		this.CACHE[key] = &CacheEntry{expire_at: this.NOW + expire, message: *value}
	}
}
func (this Proxy) cache_get(req *dns.Msg) *dns.Msg {
	this.giant.RLock()
	defer this.giant.RUnlock()

	key := this.get_cache_key(req)
	if entry, ok := this.CACHE[key]; key != "" && ok && this.NOW < entry.expire_at {
		message := entry.message
		message.Id = req.Id
		_D("GET: found valid cached entry with key: %s\n", key)
		//_D("REQUEST:%sCACHED:%s", prettify_request(req), prettify_request(&message))
		return &message
	}
	return nil
}

func (this Proxy) refused(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	for _, r := range req.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			m.SetEdns0(4096, r.(*dns.OPT).Do())
		}
	}
	m.SetRcode(req, dns.RcodeRefused)
	w.WriteMsg(m)
}
func (this Proxy) is_authorized(w dns.ResponseWriter) bool {
	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, mask := range this.ACCESS {
			if mask.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (this Proxy) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	if !this.is_authorized(w) {
		this.refused(w, request)
		return
	}
	if cached := this.cache_get(request); cached != nil {
		w.WriteMsg(cached)
		return
	}
	c := new(dns.Client)
	c.ReadTimeout = this.timeout
	c.WriteTimeout = this.timeout
	if response, rtt, err := c.Exchange(request, this.SERVERS[rand.Intn(this.s_len)]); err == nil {
		_D("%s: request took %s", w.RemoteAddr(), rtt)
		this.cache_set(request, response)
		w.WriteMsg(response)
	} else {
		this.refused(w, request)
		log.Printf("%s error: %s", w.RemoteAddr(), err)
	}
}
func _D(fmt string, v ...interface{}) {
	if DEBUG {
		log.Printf(fmt, v...)
	}
}
func prettify_request(req *dns.Msg) string {
	return fmt.Sprintf("\n------------------------\n%s\n------------------------\n", req.String())
}
func main() {

	var (
		S_SERVERS       string
		S_LISTEN        string
		S_ACCESS        string
		timeout         int
		max_entries     int64
		expire_interval int64
	)
	flag.StringVar(&S_SERVERS, "proxy", "8.8.8.8:53,8.8.4.4:53", "we proxy requests to those servers")
	flag.StringVar(&S_LISTEN, "listen", "[::]:53", "listen on (both tcp and udp)")
	flag.StringVar(&S_ACCESS, "access", "127.0.0.0/8,10.0.0.0/8", "allow those networks, use 0.0.0.0/0 to allow everything")
	flag.IntVar(&timeout, "timeout", 5, "timeout")
	flag.Int64Var(&expire_interval, "expire_interval", 300, "delete expired entries every N seconds")
	flag.BoolVar(&DEBUG, "debug", false, "enable/disable debug")
	flag.Int64Var(&max_entries, "max_cache_entries", 2000000, "max cache entries")

	flag.Parse()
	servers := strings.Split(S_SERVERS, ",")
	proxyer := Proxy{
		CACHE:       make(map[string]*CacheEntry),
		giant:       new(sync.RWMutex),
		ACCESS:      make([]*net.IPNet, 0),
		SERVERS:     servers,
		s_len:       len(servers),
		NOW:         time.Now().UTC().Unix(),
		entries:     0,
		timeout:     time.Duration(timeout) * time.Second,
		max_entries: max_entries}

	for _, mask := range strings.Split(S_ACCESS, ",") {
		_, cidr, err := net.ParseCIDR(mask)
		if err != nil {
			panic(err)
		}
		_D("added access for %s\n", mask)
		proxyer.ACCESS = append(proxyer.ACCESS, cidr)
	}
	for _, addr := range strings.Split(S_LISTEN, ",") {
		_D("listening @ %s\n", addr)
		go func() {
			if err := dns.ListenAndServe(addr, "udp", proxyer); err != nil {
				log.Fatal(err)
			}
		}()

		go func() {
			if err := dns.ListenAndServe(addr, "tcp", proxyer); err != nil {
				log.Fatal(err)
			}
		}()
	}

	for {
		proxyer.NOW = time.Now().UTC().Unix()
		if (proxyer.NOW % expire_interval) == 0 {
			proxyer.expire_cache()
		}
		time.Sleep(time.Duration(1) * time.Second)
	}
}
