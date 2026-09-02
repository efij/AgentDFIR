package realtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/version"
)

// Sink delivers one finding somewhere. Sends must never block the tail
// for long: the webhook sink has a short timeout and a bounded queue.
type Sink interface {
	Name() string
	Send(f schema.Finding) error
	Close()
}

// Alert is the wire shape every sink emits (JSON).
type Alert struct {
	Time     string         `json:"time"`
	Source   string         `json:"source"`
	Host     string         `json:"host,omitempty"`
	Finding  schema.Finding `json:"finding"`
	Producer string         `json:"producer"`
}

func envelope(host string, f schema.Finding) Alert {
	return Alert{Time: time.Now().UTC().Format(time.RFC3339Nano), Source: "agentdfir-monitor", Host: host, Finding: f,
		Producer: "agentdfir " + version.Version}
}

// ParseSink builds a sink from one --alert value:
//
//	https://host/hook            webhook (HTTP POST, JSON body)
//	syslog://host:514            syslog over UDP (RFC 5424)
//	syslog+tcp://host:514        syslog over TCP
//	/path/to/alerts.jsonl        append JSON lines
//	-                            stdout JSON lines
func ParseSink(spec, host string) (Sink, error) {
	switch {
	case spec == "-":
		return &fileSink{name: "stdout", f: os.Stdout, host: host}, nil
	case strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://"):
		return newWebhook(spec, host), nil
	case strings.HasPrefix(spec, "syslog://"):
		return newSyslog("udp", strings.TrimPrefix(spec, "syslog://"), host)
	case strings.HasPrefix(spec, "syslog+tcp://"):
		return newSyslog("tcp", strings.TrimPrefix(spec, "syslog+tcp://"), host)
	case spec == "":
		return nil, fmt.Errorf("empty alert target")
	default:
		f, err := os.OpenFile(spec, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		return &fileSink{name: "file:" + spec, f: f, host: host, closeIt: true}, nil
	}
}

// ---- file / stdout ----

type fileSink struct {
	name    string
	f       *os.File
	host    string
	closeIt bool
	mu      sync.Mutex
}

func (s *fileSink) Name() string { return s.name }
func (s *fileSink) Send(f schema.Finding) error {
	b, err := json.Marshal(envelope(s.host, f))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.f.Write(append(b, '\n'))
	return err
}
func (s *fileSink) Close() {
	if s.closeIt {
		s.f.Close()
	}
}

// ---- webhook ----

type webhookSink struct {
	url    string
	host   string
	client *http.Client
	queue  chan []byte
	wg     sync.WaitGroup
	once   sync.Once
	errs   chan error
}

func newWebhook(url, host string) *webhookSink {
	w := &webhookSink{url: url, host: host, client: &http.Client{Timeout: 5 * time.Second}, queue: make(chan []byte, 256), errs: make(chan error, 16)}
	w.wg.Add(1)
	go w.loop()
	return w
}

func (w *webhookSink) Name() string { return "webhook:" + w.url }

// Send enqueues; a full queue drops the oldest alert rather than blocking
// the tail (and reports the drop).
func (w *webhookSink) Send(f schema.Finding) error {
	b, err := json.Marshal(envelope(w.host, f))
	if err != nil {
		return err
	}
	select {
	case w.queue <- b:
	default:
		select {
		case <-w.queue:
		default:
		}
		w.queue <- b
		return fmt.Errorf("alert queue full; oldest alert dropped")
	}
	// Surface the most recent delivery error, if any (non-blocking).
	select {
	case err := <-w.errs:
		return err
	default:
		return nil
	}
}

func (w *webhookSink) loop() {
	defer w.wg.Done()
	for b := range w.queue {
		var lastErr error
		for attempt := 0; attempt < 2; attempt++ {
			req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(b))
			if err != nil {
				lastErr = err
				break
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "agentdfir/"+version.Version)
			resp, err := w.client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < 300 {
					lastErr = nil
					break
				}
				lastErr = fmt.Errorf("webhook %s: HTTP %d", w.url, resp.StatusCode)
			} else {
				lastErr = err
			}
			time.Sleep(500 * time.Millisecond)
		}
		if lastErr != nil {
			select {
			case w.errs <- lastErr:
			default:
			}
		}
	}
}

func (w *webhookSink) Close() {
	w.once.Do(func() {
		close(w.queue)
		done := make(chan struct{})
		go func() { w.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
		}
	})
}

// ---- syslog (RFC 5424, no external deps) ----

type syslogSink struct {
	network, addr, host string
	mu                  sync.Mutex
	conn                net.Conn
}

func newSyslog(network, addr, host string) (*syslogSink, error) {
	if !strings.Contains(addr, ":") {
		addr += ":514"
	}
	s := &syslogSink{network: network, addr: addr, host: host}
	if err := s.dial(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *syslogSink) dial() error {
	c, err := net.DialTimeout(s.network, s.addr, 3*time.Second)
	if err != nil {
		return err
	}
	s.conn = c
	return nil
}

func (s *syslogSink) Name() string { return "syslog:" + s.network + "://" + s.addr }

func (s *syslogSink) Send(f schema.Finding) error {
	b, err := json.Marshal(envelope(s.host, f))
	if err != nil {
		return err
	}
	pri := 4*8 + syslogSeverity(f.Severity) // facility auth(4)
	host := s.host
	if host == "" {
		host = "-"
	}
	msg := fmt.Sprintf("<%d>1 %s %s agentdfir - %s - %s\n", pri, time.Now().UTC().Format(time.RFC3339), host, f.RuleID, string(b))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		if err := s.dial(); err != nil {
			return err
		}
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := s.conn.Write([]byte(msg)); err != nil {
		s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

func (s *syslogSink) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.Close()
	}
}

func syslogSeverity(sev string) int {
	switch sev {
	case "CRITICAL":
		return 2 // crit
	case "HIGH":
		return 3 // err
	case "MEDIUM":
		return 4 // warning
	case "LOW":
		return 5 // notice
	default:
		return 6 // info
	}
}
