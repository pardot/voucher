package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	sourceEnvironment = "environment"
	sourceInstance    = "instance"
	sourceWebIdentity = "webidentity"
)

const defaultWebIdentitySessionName = "voucher"

func main() {
	ctx := context.Background()

	var (
		listen  string
		serving string

		metricslisten string
		metricsPath   string

		source string

		enableIMDSv1 bool

		envSessionTokens bool

		metadataURL string

		webIdentityTokenFile   string
		webIdentityRole        string
		webIdentitySessionName string

		targetRole string

		awsRegion string
	)

	flag.StringVar(&listen, "listen", "127.0.0.1:1800", "Address to listen for requests on")
	flag.StringVar(&serving, "serving", "169.254.169.254", "Address this is being served on, for host header validation")
	flag.StringVar(&source, "source", "environment", "Where to get upstream creds from. One of: environment, instance, webidentity")
	flag.BoolVar(&enableIMDSv1, "imdsv1-enabled", true, "Support calls via IMDSv1")

	flag.StringVar(&metricslisten, "metrics-listen", "0.0.0.0:1801", "Address to listen for metrics/health requests on")
	flag.StringVar(&metricsPath, "metrics-path", "/metrics", "Path prometheus metrics should be served on")

	flag.BoolVar(&envSessionTokens, "session-tokens", true, "environment: Use session tokens, rather than exposing the environment credentials directly")

	flag.StringVar(&metadataURL, "metadata-url", "http://169.254.169.254:8080/latest", "Base URL to upstream metadata service. Used for instance source, other proxying")

	// aws standard env var
	flag.StringVar(&webIdentityTokenFile, "web-identity-token-file", os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"), "webidentity: Path to JWT token")
	// aws standard env var
	flag.StringVar(&webIdentityRole, "web-identity-role", os.Getenv("AWS_ROLE_ARN"), "webidentity: Role for AssumeRoleWithWebIdentity call")
	flag.StringVar(&webIdentitySessionName, "web-identity-session-name", getEnvDefault("WEB_IDENTITY_SESSION_NAME", defaultWebIdentitySessionName), "webidentity: Session name")

	flag.StringVar(&targetRole, "target-role", os.Getenv("TARGET_ROLE"), "Additional role to assume in to before vouching credentials")

	flag.StringVar(&awsRegion, "region", "", "AWS region we are operating in. If not set, will attempt to discover via env vars or metadata API")

	flag.Parse()

	mreg := prometheus.NewRegistry()
	mreg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	mreg.MustRegister(prometheus.NewGoCollector())
	metrics := newMetrics()
	if err := metrics.RegisterWith(mreg); err != nil {
		log.Fatal(err)
	}
	promhttp.Handler()

	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		log.Fatalf("creating base AWS session: %v", err)
	}
	mdcli := ec2metadata.New(sess, &aws.Config{Endpoint: &metadataURL})

	if awsRegion == "" {
		log.Print("Attempting to discover AWS region")
		r, err := discoverRegion(mdcli)
		if err != nil {
			log.Fatalf("Failed to discover region: %v", err)
		}
		awsRegion = r
		log.Printf("Running in region %s", awsRegion)
	}

	sess, err = session.NewSession(&aws.Config{
		Region: &awsRegion,
		// Use the regional endpoint, so it will hit a VPC endpoint if
		// configured.
		STSRegionalEndpoint: endpoints.RegionalSTSEndpoint,
	})
	if err != nil {
		log.Fatalf("creating regional AWS session: %v", err)
	}

	var upstreamCreds *credentials.Credentials

	switch source {
	case sourceEnvironment:
		if envSessionTokens {
			// wrap the creds in something that gets temporary tokens. This prevents
			// us from exposing the raw, long-lived credentials to the consumer
			upstreamCreds = credentials.NewCredentials(&sessionTokenProvider{
				Client:       sts.New(sess),
				ExpiryWindow: 10 * time.Second,
			})
		} else {
			upstreamCreds = credentials.NewEnvCredentials()
		}
	case sourceInstance:
		ip := &ec2rolecreds.EC2RoleProvider{
			Client: ec2metadata.New(sess, &aws.Config{Endpoint: &metadataURL}),
		}
		upstreamCreds = credentials.NewCredentials(ip)
	case sourceWebIdentity:
		upstreamCreds = stscreds.NewWebIdentityCredentials(
			sess,
			webIdentityRole,
			webIdentitySessionName,
			webIdentityTokenFile,
		)
	default:
		log.Fatalf("invalid source: %s", source)
	}

	if targetRole != "" {
		upstreamCreds = stscreds.NewCredentials(sess, targetRole)
	}

	var g run.Group

	g.Add(run.SignalHandler(ctx, os.Interrupt, syscall.SIGTERM))

	{
		s, err := newServer(metrics, upstreamCreds, mdcli, awsRegion)
		if err != nil {
			log.Fatalf("initializing server: %v", err)
		}
		s.EnableIMDS1 = enableIMDSv1

		mainlis, err := net.Listen("tcp", listen)
		if err != nil {
			log.Fatalf("listening on %s: %v", listen, err)
		}
		mainsvr := http.Server{Handler: checkHostHeader(serving, s)}

		g.Add(func() error {
			log.Printf("Serving on %s", listen)
			return mainsvr.Serve(mainlis)
		}, func(error) {
			sdctx, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			if err := mainsvr.Shutdown(sdctx); err != nil {
				log.Printf("shutting down main listener: %v", err)
			}
		})
	}

	{
		obsvmux := http.NewServeMux()
		if metricsPath == "" {
			metricsPath = "/" // empty becomes just root
		}
		obsvmux.Handle(metricsPath, promhttp.InstrumentMetricHandler(mreg, promhttp.HandlerFor(mreg, promhttp.HandlerOpts{})))

		h := &healthHandler{creds: upstreamCreds}

		obsvmux.HandleFunc("/health", h.Healthy)
		obsvmux.HandleFunc("/ready", h.Ready)

		obsvlis, err := net.Listen("tcp", metricslisten)
		if err != nil {
			log.Fatalf("listening on %s: %v", metricslisten, err)
		}
		obsvsvr := http.Server{Handler: obsvmux}

		g.Add(func() error {
			log.Printf("Serving metrics on %s", metricslisten)
			return obsvsvr.Serve(obsvlis)
		}, func(error) {
			sdctx, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			if err := obsvsvr.Shutdown(sdctx); err != nil {
				log.Printf("shutting down observability listener: %v", err)
			}
		})
	}

	if err := g.Run(); err != nil {
		log.Fatal(err)
	}
}

type creds struct {
	Code            string `json:"Code"`
	LastUpdated     string `json:"LastUpdated"`
	Type            string `json:"Type"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

type awsError struct {
	Code        string `json:"Code"`
	Message     string `json:"Message"`
	LastUpdated string `json:"LastUpdated"`
}

func checkHostHeader(expectHeader string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != expectHeader {
			http.Error(w, fmt.Sprintf("Invalid request hostname: %s", r.Host), http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func getEnvDefault(envar, defaultval string) string {
	ret := os.Getenv(envar)
	if ret == "" {
		ret = defaultval
	}
	return ret
}

func discoverRegion(md *ec2metadata.EC2Metadata) (string, error) {
	if os.Getenv("AWS_REGION") != "" {
		return os.Getenv("AWS_REGION"), nil
	} else if os.Getenv("AWS_DEFAULT_REGION") != "" {
		return os.Getenv("AWS_DEFAULT_REGION"), nil
	}

	iid, err := md.GetInstanceIdentityDocument()
	if err != nil {
		return "", fmt.Errorf("getting identity document: %v", err)
	}

	return iid.Region, nil
}

type sessionTokenProvider struct {
	credentials.Expiry

	Client       stsiface.STSAPI
	ExpiryWindow time.Duration
}

func (e *sessionTokenProvider) Retrieve() (credentials.Value, error) {
	return e.RetrieveWithContext(context.Background())
}

func (e *sessionTokenProvider) RetrieveWithContext(ctx credentials.Context) (credentials.Value, error) {
	st, err := e.Client.GetSessionTokenWithContext(ctx, &sts.GetSessionTokenInput{})
	if err != nil {
		return credentials.Value{}, fmt.Errorf("getting session token: %v", err)
	}

	c, err := credentials.NewStaticCredentials(*st.Credentials.AccessKeyId, *st.Credentials.SecretAccessKey, *st.Credentials.SessionToken).Get()
	if err != nil {
		return credentials.Value{}, fmt.Errorf("creating static credentials: %v", err)
	}

	e.SetExpiration(*st.Credentials.Expiration, e.ExpiryWindow)

	return c, nil
}
