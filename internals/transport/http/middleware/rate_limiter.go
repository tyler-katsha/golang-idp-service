package middleware

import (
	"net"
	"net/http"
	"sync"

	"go.uber.org/ratelimit"
)

type IPRateLimiter struct {
	ips map[string]ratelimit.Limiter
	mux *sync.RWMutex
	rps int
}

func NewIPRateLimiter(rps int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]ratelimit.Limiter),
		mux: &sync.RWMutex{},
		rps: rps,
	}
}

func (i *IPRateLimiter) getRateLimiter(ip string) ratelimit.Limiter {
	i.mux.RLock()
	defer i.mux.RUnlock()

	limiter, exists := i.ips[ip]

	if !exists {
		i.mux.RUnlock()

		i.mux.Lock()
		limiter = ratelimit.New(i.rps)
		i.ips[ip] = limiter
		i.mux.Unlock()
	}

	return limiter
}


func LeakyBucketMiddleware(rps int) func(http.Handler) http.Handler {
	
	limiterStore := NewIPRateLimiter(rps)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			
			if err != nil {
				ip = r.RemoteAddr
			}

			// In production behind a reverse proxy/load balancer, use this instead:
			// ip = r.Header.Get("X-Forwarded-For")

			limiter := limiterStore.getRateLimiter(ip)

			limiter.Take()

			next.ServeHTTP(w,r)
		})
	}
}