package strmatcher_test

import (
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/geodata/strmatcher"
)

// Runtime routing reloads rebuild matchers in a long-lived process. A tiny rule
// must not force a collection of the unrelated heap for every matcher built.
func TestMphBuildDoesNotForceGarbageCollection(t *testing.T) {
	patterns := []struct {
		name    string
		kind    strmatcher.Type
		pattern string
		match   string
	}{
		{"full", strmatcher.Full, "service.example.test", "service.example.test"},
		{"domain", strmatcher.Domain, "example.test", "sub.example.test"},
		{"substring", strmatcher.Substr, "example", "sub.example.test"},
		{"regex", strmatcher.Regex, `^service\.example\.test$`, "service.example.test"},
	}
	for _, pattern := range patterns {
		t.Run(pattern.name, func(t *testing.T) {
			matcher, err := pattern.kind.New(pattern.pattern)
			if err != nil {
				t.Fatal(err)
			}
			value := strmatcher.NewMphValueMatcher()
			value.Add(matcher, 7)
			index := strmatcher.NewMphIndexMatcher()
			index.Add(matcher)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			if err := value.Build(); err != nil {
				t.Fatal(err)
			}
			if err := index.Build(); err != nil {
				t.Fatal(err)
			}
			runtime.ReadMemStats(&after)
			if forced := after.NumForcedGC - before.NumForcedGC; forced != 0 {
				t.Fatalf("building two small matchers forced %d process-wide garbage collections", forced)
			}
			if !value.MatchAny(pattern.match) || !index.MatchAny(pattern.match) {
				t.Fatal("expected domain stopped matching after build")
			}
			if value.MatchAny("unrelated.invalid") || index.MatchAny("unrelated.invalid") {
				t.Fatal("unrelated domain unexpectedly matched")
			}
		})
	}
}
