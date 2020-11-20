package main

import (
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/gorilla/securecookie"
)

// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
const (
	tokenTTLHeader       = "X-aws-ec2-metadata-token-ttl-seconds"
	tokenHeader          = "X-aws-ec2-metadata-token"
	maxTokenValidityTime = 6 * time.Hour

	tokenExpCookieField = "e"
)

// serves up metadata credentials
// ref: https://github.com/aws/aws-sdk-go/blob/1b7071ca4e1ebbffb85fc8187e501c3f830efe49/aws/credentials/ec2rolecreds/ec2_role_provider.go
// ref: https://github.com/aws/aws-sdk-go/blob/1b7071ca4e1ebbffb85fc8187e501c3f830efe49/aws/credentials/ec2rolecreds/ec2_role_provider_test.go
// ref: https://github.com/aws/aws-sdk-php/blob/9d2ea6cb76a003c91099eb8012a721ea3c30211c/src/Credentials/InstanceProfileProvider.php
type server struct {
	// enableIMDS1 will enable the use of requests that don't require the IMDSv2
	// token
	EnableIMDS1 bool

	// for testing, makes the API endpoint return 404. The checks can stay,
	// because they'll ignore empty header
	disableIMDSv2 bool

	mux http.Handler

	metrics *metrics
	debug   bool

	creds  *credentials.Credentials
	md     *ec2metadata.EC2Metadata
	region string

	sc *securecookie.SecureCookie

	placementAZ string
}

func newServer(metrics *metrics, creds *credentials.Credentials, md *ec2metadata.EC2Metadata, region string) (*server, error) {
	s := &server{
		metrics: metrics,
		creds:   creds,
		md:      md,
		region:  region,
	}

	// we generally have a 1:1 lifetime with the consuming process, so generate
	// a random cookie key and accept that tokens aren't valid across launches.
	// If a SDK sees a 401, it should request a new one anyway
	key := make([]byte, 32) // 128 bit random ID.
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	s.sc = securecookie.New(key, nil)
	gob.Register(time.Time{})
	// do a quick validation that securecookie works, the constructor doesn't
	// really do much and it's better to catch it before we go far
	if _, err := s.sc.Encode("key", time.Now()); err != nil {
		return nil, fmt.Errorf("initializing token signer: %v", err)
	}

	m := http.NewServeMux()
	m.HandleFunc("/latest/api/token", s.handleToken)
	m.Handle("/latest/meta-data/iam/security-credentials/", s.checkToken(http.HandlerFunc(s.handleSecurityCredentials)))
	m.Handle("/latest/meta-data/iam/security-credentials/voucher", s.checkToken(http.HandlerFunc(s.handleProxiedCredentials)))
	m.Handle("/latest/meta-data/placement/availability-zone", s.checkToken(http.HandlerFunc(s.handlePlacementAZ)))
	m.Handle("/latest/dynamic/instance-identity/document", s.checkToken(http.HandlerFunc(s.handleInstanceIdentityDocument)))
	s.mux = m

	return s, nil
}

// handleToken returns a token for IMDSv2 requests. We sign the expiration time
// and use that as the token, to avoid having to track much state but still
// supporting expiration times properly
func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	if s.disableIMDSv2 {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "Invalid request method", http.StatusBadRequest)
	}

	// default to the max, drop it if they want less
	ttl := maxTokenValidityTime
	reqTTL := r.Header.Get(tokenTTLHeader)
	if reqTTL != "" {
		ttli, err := strconv.Atoi(reqTTL)
		if err == nil && time.Duration(ttli)*time.Second < ttl {
			ttl = time.Duration(ttli) * time.Second
		}
	}

	w.Header().Set(tokenTTLHeader, fmt.Sprintf("%d", int(ttl.Truncate(time.Second).Seconds())))

	expAt := time.Now().Add(ttl)
	tok, err := s.sc.Encode(tokenExpCookieField, expAt)
	if err != nil {
		writeError(w, "encoding expiration time for token: %v", err)
	}

	fmt.Fprint(w, tok)
}

func (s *server) checkToken(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokHdr := r.Header.Get(tokenHeader)
		if tokHdr == "" {
			if s.EnableIMDS1 {
				h.ServeHTTP(w, r)
				return
			}
			http.Error(w, tokenHeader+" not set", http.StatusUnauthorized)
			return
		}
		var exp time.Time
		if err := s.sc.Decode(tokenExpCookieField, tokHdr, &exp); err != nil {
			writeError(w, "error decoding token: %v", err)
			return
		}

		if exp.Before(time.Now()) {
			http.Error(w, "token expired", http.StatusUnauthorized)
			return
		}

		h.ServeHTTP(w, r)

	})
}

// serves security-credentials, which returns the role name
func (s *server) handleSecurityCredentials(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "voucher")
}

// serves proxied credentials
func (s *server) handleProxiedCredentials(w http.ResponseWriter, r *http.Request) {
	c, err := s.creds.Get()
	if err != nil {
		s.metrics.CredServeErrorCount.Add(1)
		writeError(w, err.Error())
		return
	}
	if !c.HasKeys() {
		s.metrics.CredServeErrorCount.Add(1)
		writeError(w, "no keys in response")
		return
	}
	expAt, err := s.creds.ExpiresAt()
	if err != nil {
		if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != "ProviderNotExpirer" {
			s.metrics.CredServeErrorCount.Add(1)
			writeError(w, err.Error())
			return
		}
		// Provider doesn't have an expiration, so just make up a time.
		expAt = time.Now().Add(1 * time.Hour)
	}
	rc := creds{
		Code:            "Success",
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		Token:           c.SessionToken,
		Expiration:      expAt.Format(time.RFC3339),
		Type:            "AWS-HMAC",
		LastUpdated:     time.Now().Format(time.RFC3339),
	}
	if err := json.NewEncoder(w).Encode(&rc); err != nil {
		s.metrics.CredServeErrorCount.Add(1)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	s.metrics.CredServeCount.Add(1)
}

func (s *server) handlePlacementAZ(w http.ResponseWriter, r *http.Request) {
	// check and cache it forever, it never changes during a process lifetime
	if s.placementAZ == "" {
		azresp, err := s.md.GetMetadataWithContext(r.Context(), "placement/availability-zone")
		if err != nil {
			writeError(w, "fetching placement zone: %v", err)
		}
		s.placementAZ = azresp
	}
	fmt.Fprint(w, s.placementAZ)
}

func (s *server) handleInstanceIdentityDocument(w http.ResponseWriter, _ *http.Request) {
	// set up a bare minimum doc to use for the purpose of providing region
	// info. If more is needed, we can add it as we come across it.
	doc := ec2metadata.EC2InstanceIdentityDocument{
		Region: s.region,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		writeError(w, "encoding instance identity doc: %v", err)
		return
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.debug {
		rec := httptest.NewRecorder()

		s.mux.ServeHTTP(rec, r)

		log.Printf("%s %s - %d", r.Method, r.URL.Path, rec.Result().StatusCode)

		for k, v := range rec.Result().Header {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = rec.Body.WriteTo(w)
	} else {
		s.mux.ServeHTTP(w, r)
	}
}

func writeError(w http.ResponseWriter, format string, a ...interface{}) {
	log.Printf("error in handler: "+format, a...)
	e := awsError{
		// use a generic code, Metadata API doesn't seem to have them documented
		Code:        "Error",
		Message:     fmt.Sprintf(format, a...),
		LastUpdated: time.Now().Format(time.RFC3339),
	}
	if err := json.NewEncoder(w).Encode(&e); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
