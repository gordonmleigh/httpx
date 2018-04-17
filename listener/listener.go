package listener

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

// options represents the options for a listener.
type options struct {
	handler   http.Handler
	addr      []*interfaceInfo
	tlsConfig *tls.Config
	logger    byolog.Logger
}

// OptionFunc represents a function which configures options.
type OptionFunc func(opt *options) error

// SetHandler sets the request handler for the listener.
func SetHandler(handler http.Handler) OptionFunc {
	return func(opt *options) error {
		opt.handler = handler
		return nil
	}
}

// AddInterface adds an interface to the listener.
func AddInterface(addr string) OptionFunc {
	return func(opt *options) error {
		iface, err := makeInterfaceInfo(addr)
		if err != nil {
			return err
		}
		opt.addr = append(opt.addr, iface)
		return nil
	}
}

// SetTLSConfig sets the tls configuration for the listener.
func SetTLSConfig(tlsConfig *tls.Config) OptionFunc {
	return func(opt *options) error {
		opt.tlsConfig = tlsConfig
		return nil
	}
}

// SetLogger sets the logger instance for the listener.
func SetLogger(logger byolog.Logger) OptionFunc {
	return func(opt *options) error {
		opt.logger = logger
		return nil
	}
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

// New creates a new listener
func New(optionSetters ...OptionFunc) (Listener, error) {
	opts := &options{}
	for _, opt := range optionSetters {
		opt(opts)
	}

	if opts.logger == nil {
		opts.logger = byolog.Nop()
	}

	if len(opts.addr) < 1 {
		return nil, errors.New("a listener needs at least 1 interface")
	}

	for _, iface := range opts.addr {
		if iface.tls {
			if opts.tlsConfig == nil {
				return nil, errors.New("tls config must be provided for secure interfaces")
			}
			break
		}
	}

	if len(opts.addr) == 1 {
		return newListener(opts)
	}
	return newMultiListener(opts)
}

type listener struct {
	*http.Server
	tls    bool
	logger byolog.Logger
}

// newListener creates a new Listener.
func newListener(opts *options) (Listener, error) {
	if len(opts.addr) != 1 {
		return nil, errors.Errorf("expected exactly 1 interface, given %d", len(opts.addr))
	}

	opts.logger = opts.logger.Named("listener").With(byolog.NewField("addr", opts.addr[0]))
	opts.logger.Debug("creating listener")

	return &listener{
		Server: &http.Server{
			Addr:      opts.addr[0].authority,
			Handler:   opts.handler,
			TLSConfig: opts.tlsConfig,
		},
		tls:    opts.addr[0].tls,
		logger: opts.logger,
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

// newMultiListener creates a listener that listens on multiple addresses.  If
// any internal http.Server instance ends, all instances end.
func newMultiListener(opts *options) (Listener, error) {
	if len(opts.addr) < 1 {
		return nil, errors.Errorf("expected at least 1 interface, given %d", len(opts.addr))
	}

	opts.logger = opts.logger.Named("multilistener").With(byolog.NewField("addrs", opts.addr))
	opts.logger.Debug("creating multilistener")

	multi := &multiListener{
		errors:    make(chan error, 1),
		waitGroup: &sync.WaitGroup{},
		logger:    opts.logger,
	}

	for _, addr := range opts.addr {
		listenerOpts := *opts
		listenerOpts.addr = []*interfaceInfo{addr}

		l, err := newListener(&listenerOpts)
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

// interfaceInfo describes an inteface to listen on.
type interfaceInfo struct {
	authority string
	tls       bool
}

// ParseServerAddress reads useful information from a listen address
func makeInterfaceInfo(addr string) (*interfaceInfo, error) {
	info := &interfaceInfo{}

	addrURL, err := url.Parse(addr)
	if err != nil {
		return nil, errors.Wrapf(err, "can't parse provided URL '%s'", addr)
	}
	info.authority = addrURL.Host

	if addrURL.Scheme == "https" {
		info.tls = true
	} else if addrURL.Scheme != "http" || addrURL.Path != "" {
		return nil, errors.Errorf("invalid listen address '%s' (must be https or http and not include path)", addr)
	}

	return info, nil
}

func (i *interfaceInfo) String() string {
	s := "http"
	if i.tls {
		s += "s"
	}
	s += "://" + i.authority
	return s
}
