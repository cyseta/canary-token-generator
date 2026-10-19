package geoip

import (
	"log/slog"
	"net"
	"os"

	"github.com/oschwald/geoip2-golang"
)

type Location struct {
	Country string  `json:"country"`
	City    string  `json:"city"`
	ISOCode string  `json:"iso_code"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
}

type Provider interface {
	Lookup(ipStr string) Location
	Close() error
}

type MaxMindProvider struct {
	db *geoip2.Reader
}

func (m *MaxMindProvider) Lookup(ipStr string) Location {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Location{}
	}

	record, err := m.db.City(ip)
	if err != nil {
		return Location{}
	}

	loc := Location{
		Country: record.Country.Names["en"],
		City:    record.City.Names["en"],
		ISOCode: record.Country.IsoCode,
		Lat:     record.Location.Latitude,
		Lon:     record.Location.Longitude,
	}
	return loc
}

func (m *MaxMindProvider) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

type NopProvider struct{}

func (n *NopProvider) Lookup(ipStr string) Location {
	// Nop fallback: basic private IP detection or empty
	ip := net.ParseIP(ipStr)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		return Location{
			Country: "Internal Network",
			City:    "Localhost",
			ISOCode: "LAN",
		}
	}
	return Location{
		Country: "Unknown",
		City:    "Unknown",
		ISOCode: "XX",
	}
}

func (n *NopProvider) Close() error {
	return nil
}

func NewProvider(path string) Provider {
	if path == "" {
		slog.Info("no GeoIP DB path configured, using Nop GeoIP provider")
		return &NopProvider{}
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		slog.Warn("GeoIP database file not found, using Nop GeoIP provider", "path", path)
		return &NopProvider{}
	}

	db, err := geoip2.Open(path)
	if err != nil {
		slog.Warn("failed to open GeoIP database, falling back to Nop provider", "error", err)
		return &NopProvider{}
	}

	slog.Info("GeoIP MaxMind database loaded successfully", "path", path)
	return &MaxMindProvider{db: db}
}
