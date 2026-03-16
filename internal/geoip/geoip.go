package geoip

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Location holds geographic info about an IP address.
type Location struct {
	IP      string
	Country string
	City    string
	ASN     string
	ISP     string
	Lat     float64
	Lon     float64
}

// Resolver resolves IP addresses to geographic locations.
type Resolver struct {
	mu      sync.RWMutex
	cache   map[string]*Location
	mmdb    *maxminddb.Reader
	client  *http.Client
	useMM   bool
}

// New creates a Resolver. If mmdbPath is empty or unreadable,
// falls back to the ip-api.com free API.
func New(mmdbPath string) *Resolver {
	r := &Resolver{
		cache:  make(map[string]*Location),
		client: &http.Client{Timeout: 5 * time.Second},
	}
	if mmdbPath != "" {
		db, err := maxminddb.Open(mmdbPath)
		if err == nil {
			r.mmdb  = db
			r.useMM = true
		}
	}
	return r
}

// Close closes the MaxMind database if open.
func (r *Resolver) Close() {
	if r.mmdb != nil {
		r.mmdb.Close()
	}
}

// Lookup returns location info for an IP address.
// Results are cached in memory.
func (r *Resolver) Lookup(ipStr string) *Location {
	// Check cache first
	r.mu.RLock()
	if loc, ok := r.cache[ipStr]; ok {
		r.mu.RUnlock()
		return loc
	}
	r.mu.RUnlock()

	var loc *Location
	if r.useMM {
		loc = r.lookupMaxMind(ipStr)
	} else {
		loc = r.lookupAPI(ipStr)
	}

	if loc == nil {
		loc = &Location{IP: ipStr, Country: "Unknown"}
	}

	// Store in cache
	r.mu.Lock()
	r.cache[ipStr] = loc
	r.mu.Unlock()

	return loc
}

// mmRecord is the MaxMind DB record structure.
type mmRecord struct {
	Country struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Traits struct {
		ISP              string `maxminddb:"isp"`
		AutonomousSystem string `maxminddb:"autonomous_system_organization"`
		ASN              uint   `maxminddb:"autonomous_system_number"`
	} `maxminddb:"traits"`
}

func (r *Resolver) lookupMaxMind(ipStr string) *Location {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	var record mmRecord
	if err := r.mmdb.Lookup(ip, &record); err != nil {
		return nil
	}
	country := record.Country.Names["en"]
	city    := record.City.Names["en"]
	asn     := fmt.Sprintf("AS%d", record.Traits.ASN)
	isp     := record.Traits.ISP
	if isp == "" {
		isp = record.Traits.AutonomousSystem
	}
	return &Location{
		IP:      ipStr,
		Country: country,
		City:    city,
		ASN:     asn,
		ISP:     isp,
		Lat:     record.Location.Latitude,
		Lon:     record.Location.Longitude,
	}
}

// apiResponse matches the ip-api.com JSON response.
type apiResponse struct {
	Status  string  `json:"status"`
	Country string  `json:"country"`
	City    string  `json:"city"`
	ISP     string  `json:"isp"`
	Org     string  `json:"org"`
	AS      string  `json:"as"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

func (r *Resolver) lookupAPI(ipStr string) *Location {
	providers := []func(string) *Location{
		r.lookupIPAPI,      // 45/min
		r.lookupIPWHO,      // 1/sec (Suggested)
		r.lookupIPQuery,    // Performance fallback
		r.lookupFreeIPAPI,  // Original fallback
		r.lookupCountryIS,  // Minimalist fallback
	}

	for _, p := range providers {
		loc := p(ipStr)
		if loc != nil && loc.Country != "Unknown" && loc.Country != "" {
			return loc
		}
	}
	return nil
}

func (r *Resolver) lookupIPAPI(ipStr string) *Location {
	// For RDP/local testing or Ngrok forwarding, loopback/private IPs like
	// 127.0.0.1 or 192.168.x.x will be identified as internal or Ngrok.
	// You indicated you DON'T want to pull your own machine's public IP
	// to avoid exposing yourself. We will parse it simply as a Proxy/Tunnel.
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return &Location{IP: ipStr, Country: "Unknown"}
	}
	
	if ip.IsLoopback() || ip.IsPrivate() {
		// Attempt to check if Ngrok is running locally, which means
		// we can confidently say this is a Proxy/Tunnel.
		resp, err := r.client.Get("http://127.0.0.1:4040/api/tunnels")
		if err == nil {
			resp.Body.Close()
			return &Location{
				IP:      ipStr,
				Country: "Ngrok Tunnel",
				City:    "External Proxy",
				ISP:     "Ngrok API",
			}
		}

		// Otherwise it's just a local network / RDP
		return &Location{
			IP:      ipStr,
			Country: "Private/Local",
			City:    "Local Network",
			ISP:     "Internal",
		}
	}

	url  := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city,isp,org,as,lat,lon", ipStr)
	resp, err := r.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var data apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}
	if data.Status != "success" {
		return nil
	}
	return &Location{
		IP:      ipStr,
		Country: data.Country,
		City:    data.City,
		ASN:     data.AS,
		ISP:     data.ISP,
		Lat:     data.Lat,
		Lon:     data.Lon,
	}
}

func (r *Resolver) lookupFreeIPAPI(ipStr string) *Location {
	url := fmt.Sprintf("https://freeipapi.com/api/json/%s", ipStr)
	resp, err := r.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var data struct {
		CountryName string  `json:"countryName"`
		CityName    string  `json:"cityName"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}
	
	if data.CountryName == "" || data.CountryName == "-" {
		return nil
	}

	return &Location{
		IP:      ipStr,
		Country: data.CountryName,
		City:    data.CityName,
		Lat:     data.Latitude,
		Lon:     data.Longitude,
	}
}

func (r *Resolver) lookupIPWHO(ipStr string) *Location {
	url := fmt.Sprintf("http://ipwho.is/%s", ipStr)
	resp, err := r.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var data struct {
		Success bool    `json:"success"`
		Country string  `json:"country"`
		City    string  `json:"city"`
		ISP     string  `json:"connection.isp"`
		Lat     float64 `json:"latitude"`
		Lon     float64 `json:"longitude"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}
	if !data.Success {
		return nil
	}
	return &Location{
		IP:      ipStr,
		Country: data.Country,
		City:    data.City,
		Lat:     data.Lat,
		Lon:     data.Lon,
	}
}

func (r *Resolver) lookupIPQuery(ipStr string) *Location {
	url := fmt.Sprintf("https://api.ipquery.io/%s", ipStr)
	resp, err := r.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var data struct {
		IP       string `json:"ip"`
		Location struct {
			Country   string  `json:"country"`
			City      string  `json:"city"`
			Latitude  float64 `json:"latitude"`
			Longitude float64 `json:"longitude"`
		} `json:"location"`
		ISP struct {
			ISP string `json:"isp"`
			ASN string `json:"asn"`
		} `json:"isp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}
	return &Location{
		IP:      ipStr,
		Country: data.Location.Country,
		City:    data.Location.City,
		ASN:     data.ISP.ASN,
		ISP:     data.ISP.ISP,
		Lat:     data.Location.Latitude,
		Lon:     data.Location.Longitude,
	}
}

func (r *Resolver) lookupCountryIS(ipStr string) *Location {
	url := fmt.Sprintf("https://api.country.is/%s", ipStr)
	resp, err := r.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var data struct {
		Country string `json:"country"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}
	
	// Convert code to name if possible, or just use code
	countryName := data.Country
	if countryName == "" {
		return nil
	}

	return &Location{
		IP:      ipStr,
		Country: countryName,
	}
}

// FlagEmoji returns a flag emoji for a country name.
// Limited set covering most common attacker origins.
func FlagEmoji(country string) string {
	flags := map[string]string{
		"China":          "🇨🇳",
		"United States":  "🇺🇸",
		"Russia":         "🇷🇺",
		"Germany":        "🇩🇪",
		"Netherlands":    "🇳🇱",
		"France":         "🇫🇷",
		"United Kingdom": "🇬🇧",
		"Brazil":         "🇧🇷",
		"India":          "🇮🇳",
		"South Korea":    "🇰🇷",
		"Vietnam":        "🇻🇳",
		"Iran":           "🇮🇷",
		"Ukraine":        "🇺🇦",
		"Romania":        "🇷🇴",
		"Turkey":         "🇹🇷",
		"Indonesia":      "🇮🇩",
		"Japan":          "🇯🇵",
		"Canada":         "🇨🇦",
		"Singapore":      "🇸🇬",
		"Hong Kong":      "🇭🇰",
	}
	if flag, ok := flags[country]; ok {
		return flag
	}
	return "🌐"
}

// LookupSelf resolves the location of the current server's public IP.
func (r *Resolver) LookupSelf() *Location {
	// Try to get public IP from a few reliable "what is my ip" services
	urls := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://ipinfo.io/ip",
	}

	var publicIP string
	for _, url := range urls {
		resp, err := r.client.Get(url)
		if err == nil {
			b, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil && len(b) > 0 {
				publicIP = strings.TrimSpace(string(b))
				if net.ParseIP(publicIP) != nil {
					break
				}
			}
		}
	}

	if publicIP == "" {
		// Fallback to the provider's "self" detection if supported (like ip-api)
		return r.lookupIPAPI("") 
	}

	return r.Lookup(publicIP)
}
