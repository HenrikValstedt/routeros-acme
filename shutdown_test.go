package main

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestShutdownWaitsForRunningJob(t *testing.T) {
	st, _ := OpenStore(t.TempDir())
	m := NewManager(st, t.TempDir())
	var finished, queuedRan, lateRan atomic.Bool
	started := make(chan struct{})
	m.Go(func() { close(started); time.Sleep(300 * time.Millisecond); finished.Store(true) })
	<-started
	m.Go(func() { queuedRan.Store(true) }) // queued behind the running job
	t0 := time.Now()
	if !m.Shutdown(2 * time.Second) {
		t.Fatal("shutdown timed out")
	}
	if !finished.Load() {
		t.Fatal("shutdown returned before the running job finished")
	}
	if queuedRan.Load() {
		t.Fatal("a job queued before the stop must not start after it")
	}
	m.Go(func() { lateRan.Store(true) })
	time.Sleep(50 * time.Millisecond)
	if lateRan.Load() {
		t.Fatal("no new jobs after shutdown")
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestShutdownTimeout(t *testing.T) {
	st, _ := OpenStore(t.TempDir())
	m := NewManager(st, t.TempDir())
	m.Go(func() { time.Sleep(time.Second) })
	time.Sleep(20 * time.Millisecond)
	if m.Shutdown(100 * time.Millisecond) {
		t.Fatal("should report that the job did not finish in time")
	}
}

func TestDeployRoundStopsBetweenRouters(t *testing.T) {
	st, _ := OpenStore(t.TempDir())
	_ = st.Update(func(c *Config) error {
		c.Certs = []*Cert{{ID: "c1", Name: "x", Fingerprint: "f"}}
		for _, id := range []string{"r1", "r2", "r3"} {
			c.Routers = append(c.Routers, &Router{ID: id, Name: id, Enabled: true, Host: "127.0.0.1", APIPort: 1,
				ServiceUser: "u", Secret: "v1:x", Pins: []string{"p"}, CertID: "c1"})
		}
		return nil
	})
	m := NewManager(st, t.TempDir())
	m.stopping.Store(true)
	m.deployOutdated()
	for _, r := range st.Snapshot().Routers {
		if r.LastError != "" {
			t.Fatalf("router %s was attempted after the stop: %s", r.ID, r.LastError)
		}
	}
}
