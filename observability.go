package main

import (
	"net/http"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	CredServeCount      prometheus.Counter
	CredServeErrorCount prometheus.Counter
}

func newMetrics() *metrics {
	return &metrics{
		CredServeCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "voucher",
				Name:      "cred_serve_count",
				Help:      "Number of times credentials have been requested from the endpoint",
			},
		),
		CredServeErrorCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "voucher",
				Name:      "cred_serve_error_count",
				Help:      "Number of times we've served an error from the credentials endpoint",
			},
		),
	}
}

func (m *metrics) RegisterWith(r prometheus.Registerer) error {
	if err := r.Register(m.CredServeCount); err != nil {
		return errors.Wrap(err, "failed to register prometheus credServeCount collector")
	}
	if err := r.Register(m.CredServeErrorCount); err != nil {
		return errors.Wrap(err, "failed to register prometheus credServeErrorCount collector")
	}
	return nil
}

type healthHandler struct {
	creds *credentials.Credentials
}

func (h *healthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	// re-use health check for this currently
	h.Healthy(w, r)

}

func (h *healthHandler) Healthy(w http.ResponseWriter, r *http.Request) {
	if !h.creds.IsExpired() {
		// unexpired creds, we're good
		return
	}

	if _, err := h.creds.GetWithContext(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
