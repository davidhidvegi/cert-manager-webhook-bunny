package main

import (
	"strings"
	"testing"

	"github.com/davidhidvegi/cert-manager-webhook-bunny/internal"
)

func TestFindZoneAndHost(t *testing.T) {
	tests := []struct {
		name       string
		fqdn       string
		responses  map[string]internal.ZoneResponse
		wantZone   string
		wantHost   string
		wantLookup []string
		wantErr    string
	}{
		{
			name: "apex zone",
			fqdn: "_acme-challenge.example.com.",
			responses: map[string]internal.ZoneResponse{
				"example.com": {
					Items: []internal.Items{{Domain: "example.com", Id: 1}},
				},
			},
			wantZone:   "example.com",
			wantHost:   "_acme-challenge",
			wantLookup: []string{"example.com"},
		},
		{
			name: "delegated subzone",
			fqdn: "_acme-challenge.podinfo.hzpg.connectedcare.io.",
			responses: map[string]internal.ZoneResponse{
				"podinfo.hzpg.connectedcare.io": {},
				"hzpg.connectedcare.io": {
					Items: []internal.Items{{Domain: "hzpg.connectedcare.io", Id: 2}},
				},
			},
			wantZone:   "hzpg.connectedcare.io",
			wantHost:   "_acme-challenge.podinfo",
			wantLookup: []string{"podinfo.hzpg.connectedcare.io", "hzpg.connectedcare.io"},
		},
		{
			name: "prefers longest exact zone match",
			fqdn: "_acme-challenge.api.dev.example.com.",
			responses: map[string]internal.ZoneResponse{
				"api.dev.example.com": {
					Items: []internal.Items{{Domain: "api.dev.example.com", Id: 3}},
				},
				"dev.example.com": {
					Items: []internal.Items{{Domain: "dev.example.com", Id: 4}},
				},
			},
			wantZone:   "api.dev.example.com",
			wantHost:   "_acme-challenge",
			wantLookup: []string{"api.dev.example.com"},
		},
		{
			name: "filters partial search matches",
			fqdn: "_acme-challenge.dev.example.com.",
			responses: map[string]internal.ZoneResponse{
				"dev.example.com": {
					Items: []internal.Items{{Domain: "not-dev.example.com", Id: 5}, {Domain: "dev.example.com", Id: 6}},
				},
			},
			wantZone:   "dev.example.com",
			wantHost:   "_acme-challenge",
			wantLookup: []string{"dev.example.com"},
		},
		{
			name:    "rejects invalid fqdn",
			fqdn:    "example.com.",
			wantErr: "unable to parse",
		},
		{
			name: "returns not found when no zone matches",
			fqdn: "_acme-challenge.example.com.",
			responses: map[string]internal.ZoneResponse{
				"example.com": {},
			},
			wantLookup: []string{"example.com"},
			wantErr:    "unable to find a matching Bunny zone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lookups []string
			zone, host, err := findZoneAndHost(tt.fqdn, func(domain string) (internal.ZoneResponse, error) {
				lookups = append(lookups, domain)
				if resp, ok := tt.responses[domain]; ok {
					return resp, nil
				}
				return internal.ZoneResponse{}, nil
			})

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if zone.Domain != tt.wantZone {
					t.Fatalf("zone domain = %q, want %q", zone.Domain, tt.wantZone)
				}
				if host != tt.wantHost {
					t.Fatalf("host = %q, want %q", host, tt.wantHost)
				}
			}

			if strings.Join(lookups, ",") != strings.Join(tt.wantLookup, ",") {
				t.Fatalf("lookups = %v, want %v", lookups, tt.wantLookup)
			}
		})
	}
}
