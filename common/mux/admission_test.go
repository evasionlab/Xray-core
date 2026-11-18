package mux

import (
	"testing"

	"github.com/xtls/xray-core/common/signal/done"
)

func TestClientWorkerAdmissionTracksSessionLifecycle(t *testing.T) {
	strategy := ClientStrategy{MaxConcurrency: 1, MaxConnection: 2}
	worker := &ClientWorker{
		sessionManager: NewSessionManager(),
		strategy:       strategy,
		done:           done.New(),
	}
	if worker.IsFull() {
		t.Fatal("new worker rejects admission")
	}

	first := worker.sessionManager.Allocate(&strategy)
	if first == nil || !worker.IsFull() {
		t.Fatal("allocation did not fill the worker")
	}
	worker.sessionManager.Remove(false, first.ID)
	if worker.IsFull() {
		t.Fatal("released slot did not reopen admission")
	}

	next := worker.sessionManager.Allocate(&strategy)
	if next == nil {
		t.Fatal("worker rejected an available slot")
	}
	worker.sessionManager.Remove(false, next.ID)
	if !worker.IsFull() {
		t.Fatal("exhausted lifetime limit reopened admission")
	}

	worker = &ClientWorker{sessionManager: NewSessionManager(), done: done.New()}
	if err := worker.Close(); err != nil || !worker.IsFull() {
		t.Fatal("closing worker accepts admission")
	}
}

func BenchmarkLargeMuxPicker(b *testing.B) {
	strategy := ClientStrategy{MaxConcurrency: 1, MaxConnection: 128}
	picker := IncrementalWorkerPicker{workers: make([]*ClientWorker, 6000)}
	for i := range picker.workers {
		worker := &ClientWorker{
			sessionManager: NewSessionManager(),
			strategy:       strategy,
			done:           done.New(),
		}
		if i < len(picker.workers)-1 {
			worker.sessionManager.Allocate(&strategy)
		}
		picker.workers[i] = worker
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = picker.pickInternal()
		}
	})
}
