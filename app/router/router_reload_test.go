package router

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestReloadRulesFullReplaceIsAtomicOnBuildError(t *testing.T) {
	r := &Router{
		domainStrategy: Config_IpOnDemand,
		balancers:      map[string]*Balancer{},
		rules: []*Rule{
			{Tag: "old", RuleTag: "old-rule"},
		},
	}

	err := r.ReloadRules(&Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{BalancingTag: "missing-balancer"},
				RuleTag:   "bad-rule",
				Networks:  []net.Network{net.Network_TCP},
			},
		},
	}, false)
	if err == nil {
		t.Fatal("ReloadRules should reject a rule referencing a missing balancer")
	}

	if r.domainStrategy != Config_IpOnDemand {
		t.Fatalf("domainStrategy changed after failed reload: got %v", r.domainStrategy)
	}
	if len(r.rules) != 1 || r.rules[0].RuleTag != "old-rule" || r.rules[0].Tag != "old" {
		t.Fatalf("rules changed after failed reload: %#v", r.rules)
	}
	if len(r.balancers) != 0 {
		t.Fatalf("balancers changed after failed reload: %#v", r.balancers)
	}
}

func TestReloadRulesFullReplaceUpdatesDomainStrategyOnSuccess(t *testing.T) {
	r := &Router{
		domainStrategy: Config_AsIs,
		balancers:      map[string]*Balancer{},
		rules: []*Rule{
			{Tag: "old", RuleTag: "old-rule"},
		},
	}

	err := r.ReloadRules(&Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{Tag: "new"},
				RuleTag:   "new-rule",
				Networks:  []net.Network{net.Network_TCP},
			},
		},
	}, false)
	if err != nil {
		t.Fatalf("ReloadRules returned error: %v", err)
	}

	if r.domainStrategy != Config_IpIfNonMatch {
		t.Fatalf("domainStrategy was not updated: got %v", r.domainStrategy)
	}
	if len(r.rules) != 1 || r.rules[0].RuleTag != "new-rule" || r.rules[0].Tag != "new" {
		t.Fatalf("rules were not replaced: %#v", r.rules)
	}
}
