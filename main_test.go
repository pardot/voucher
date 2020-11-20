package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/awstesting/unit"
)

func TestCheckHostHeader(t *testing.T) {
	h := checkHostHeader("example.net", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// let it 200
	}))

	for _, tc := range []struct {
		Name       string
		Request    *http.Request
		WantStatus int
	}{
		{
			Name:       "Good",
			Request:    httptest.NewRequest("GET", "http://example.net/", nil),
			WantStatus: 200,
		},
		{
			Name:       "Bad",
			Request:    httptest.NewRequest("GET", "http://bad.net/", nil),
			WantStatus: 403,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.Request)
			if rec.Result().StatusCode != tc.WantStatus {
				t.Errorf("want: %d, got: %d", tc.WantStatus, rec.Result().StatusCode)
			}
		})
	}
}

func TestDiscoverRegion(t *testing.T) {
	currRegion := os.Getenv("AWS_REGION")
	currDefaultRegion := os.Getenv("AWS_DEFAULT_REGION")
	defer func() {
		os.Setenv("AWS_REGION", currRegion)
		os.Setenv("AWS_DEFAULT_REGION", currDefaultRegion)
	}()

	svr := httptest.NewServer(&mockMetadataServer{
		instanceDocument: `{"region": "eu-west-2"}`,
	})

	c := ec2metadata.New(unit.Session, &aws.Config{Endpoint: aws.String(svr.URL + "/latest")})

	rg, err := discoverRegion(c)
	if err != nil {
		t.Errorf("unexpected discovering region: %v", err)
	}
	if rg != "eu-west-2" {
		t.Errorf("expected eu-west-2, got %s", rg)
	}

	os.Setenv("AWS_DEFAULT_REGION", "us-east-1")

	rg, err = discoverRegion(c)
	if err != nil {
		t.Errorf("unexpected discovering region: %v", err)
	}
	if rg != "us-east-1" {
		t.Errorf("expected us-east-1, got %s", rg)
	}

	os.Setenv("AWS_REGION", "us-east-2")

	rg, err = discoverRegion(c)
	if err != nil {
		t.Errorf("unexpected discovering region: %v", err)
	}
	if rg != "us-east-2" {
		t.Errorf("expected us-east-2, got %s", rg)
	}
}
