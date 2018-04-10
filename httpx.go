package httpx

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/gordonmleigh/byolog"
	"github.com/pkg/errors"
)

// Listener represents an http.Server instance listening on a specific address.
type Listener interface {
	Start() error
	Stop(gracefulTimeout time.Duration) error
}

type listener struct {
	*http.Server
	tls    bool
	logger byolog.Logger
}

// NewListener creates a new Listener.
func NewListener(handler http.Handler, addr string, tlsConfig *tls.Config, logger byolog.Logger) (Listener, error) {
	if logger == nil {
		logger = byolog.Nop()
	}
	logger = logger.Named("listener").With(byolog.NewField("addr", addr))
	logger.Debug("creating listener")

	host, tls, err := ParseServerAddress(addr)
	if err != nil {
		return nil, err
	}

	return &listener{
		Server: &http.Server{
			Addr:      host,
			Handler:   handler,
			TLSConfig: tlsConfig,
		},
		tls:    tls,
		logger: logger,
	}, nil
}

// Start starts the listener.
func (l *listener) Start() error {
	var err error

	if l.tls {
		l.logger.Info("starting secure listener...")
		err = l.ListenAndServeTLS("", "")
	} else {
		l.logger.Info("starting unsecure listener...")
		err = l.ListenAndServe()
	}

	l.logger.Error("listener terminated", byolog.NewField("err", err))
	return errors.Wrap(err, "listener terminated")
}

// Stop stops the listener.
func (l *listener) Stop(timeout time.Duration) error {
	l.logger.Info("stop requested", byolog.NewField("timeout", timeout))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err := l.Shutdown(ctx)
	if err != nil {
		l.logger.Error("graceful shutdown failed", byolog.NewField("err", err))
		err = l.Close()
	}
	if err != nil {
		l.logger.Error("forced shutdown failed", byolog.NewField("err", err))
	}
	return err
}

type multiListener struct {
	listeners []Listener
	err       error
	errors    chan error
	waitGroup *sync.WaitGroup
	logger    byolog.Logger
}

// NewMultiListener creates a listener that listens on multiple addresses.  If
// any internal http.Server instance ends, all instances end.
func NewMultiListener(handler http.Handler, addresses []string, tlsConfig *tls.Config, logger byolog.Logger) (Listener, error) {
	if logger == nil {
		logger = byolog.Nop()
	}
	logger = logger.Named("multiListener")
	logger.Debug("creating multi listener", byolog.NewField("addresses", addresses))

	multi := &multiListener{
		errors:    make(chan error, 1),
		waitGroup: &sync.WaitGroup{},
		logger:    logger,
	}

	for _, addr := range addresses {
		l, err := NewListener(handler, addr, tlsConfig, multi.logger)
		if err != nil {
			return nil, errors.Wrap(err, "can't create listener")
		}
		multi.listeners = append(multi.listeners, l)
	}

	return multi, nil
}

// Start starts the listener.
func (m *multiListener) Start() error {
	m.logger.Info("starting multi-listener...")

	for _, l := range m.listeners {
		go (func(l Listener) {
			m.waitGroup.Add(1)
			defer m.waitGroup.Done()
			err := l.Start()
			// non-blocking send (channel only accepts one error)
			select {
			case m.errors <- err:
			default:
			}
		})(l)
	}
	err := <-m.errors
	m.waitGroup.Wait()
	close(m.errors)
	return err
}

// Stop stops the listener.
func (m *multiListener) Stop(timeout time.Duration) error {
	m.logger.Info("stop requested", byolog.NewField("timeout", timeout))

	for _, l := range m.listeners {
		go (func(l Listener) {
			// don't consider the server closed until Stop() returns nicely
			m.waitGroup.Add(1)
			defer m.waitGroup.Done()
			l.Stop(timeout)
		})(l)
	}
	m.waitGroup.Wait()
	return nil
}

// ParseServerAddress reads useful information from a listen address
func ParseServerAddress(addr string) (authority string, tls bool, err error) {
	tls = false

	addrURL, err := url.Parse(addr)
	if err != nil {
		err = errors.Wrapf(err, "can't parse provided URL '%s'", addr)
		return
	}

	if addrURL.Scheme == "https" {
		tls = true
	} else if addrURL.Scheme != "http" || addrURL.Path != "" {
		err = errors.Errorf("invalid listen address '%s' (must be https or http and not include path)", addr)
		return
	}

	return addrURL.Host, tls, nil
}

// TerminateOnSigint closes the listener when SIGINT (ctrl+c) is received.
func TerminateOnSigint(l Listener, gracefulTimeout time.Duration) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		l.Stop(gracefulTimeout)
	}()
}
