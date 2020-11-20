package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/awstesting/unit"
)

func TestPassthrough(t *testing.T) {
	for _, tc := range []struct {
		Name          string
		AllowIMDSv1   bool
		DisableIMDSv2 bool
	}{
		{
			Name:        "Default Behaviour",
			AllowIMDSv1: true,
		},
		{
			Name:          "IMDSv1 Only",
			AllowIMDSv1:   true,
			DisableIMDSv2: true,
		},
		{
			Name:        "IMDSv2 Only",
			AllowIMDSv1: false,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			mdsvr := httptest.NewServer(&mockMetadataServer{
				placementAZ: `us-east-1e`,
			})

			svr, err := newServer(newMetrics(), nil, ec2metadata.New(unit.Session, &aws.Config{Endpoint: aws.String(mdsvr.URL + "/latest")}), "eu-west-2")
			if err != nil {
				t.Fatal(err)
			}
			svr.EnableIMDS1 = tc.AllowIMDSv1
			svr.disableIMDSv2 = tc.DisableIMDSv2
			svr.debug = true

			vsvr := httptest.NewServer(svr)

			vmdc := ec2metadata.New(unit.Session, &aws.Config{Endpoint: aws.String(vsvr.URL + "/latest")})

			iid, err := vmdc.GetInstanceIdentityDocument()
			if err != nil {
				t.Fatalf("getting instance identity doc from voucher: %v", err)
			}
			if iid.Region != "eu-west-2" {
				t.Errorf("want instance identity doc region eu-west-2, got: %s", iid.Region)
			}

			paz, err := vmdc.GetMetadata("placement/availability-zone")
			if err != nil {
				t.Fatalf("error getting placement az: %v", err)
			}
			if paz != "us-east-1e" {
				t.Errorf("want placement zone us-east-1e, got: %s", iid.Region)
			}
		})
	}
}

type mockMetadataServer struct {
	init sync.Once

	mux *http.ServeMux

	instanceDocument string
	placementAZ      string
}

func (m *mockMetadataServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.init.Do(func() {
		m.mux = http.NewServeMux()

		m.mux.HandleFunc("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, _ *http.Request) {
			if m.instanceDocument == "" {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			fmt.Fprint(w, m.instanceDocument)
		})

		m.mux.HandleFunc("/latest/meta-data/placement/availability-zone", func(w http.ResponseWriter, _ *http.Request) {
			if m.placementAZ == "" {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			fmt.Fprint(w, m.placementAZ)
		})

	})
	m.mux.ServeHTTP(w, r)
}
