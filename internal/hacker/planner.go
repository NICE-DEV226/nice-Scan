package hacker

import (
	"sort"
	"sync"
)

type Planner struct {
	mu          sync.Mutex
	actions     []Action
	done        map[string]bool
	destructive bool
}

func NewPlanner(actions ...Action) *Planner {
	sorted := make([]Action, len(actions))
	copy(sorted, actions)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Metadata().Priority < sorted[j].Metadata().Priority
	})
	return &Planner{
		actions: sorted,
		done:    make(map[string]bool),
	}
}

// AllowDestructive records the operator's --destructive consent. Without
// it the planner withholds every action flagged Destructive at dispatch
// time — registering or spawning such an action is not consent.
func (p *Planner) AllowDestructive(allowed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.destructive = allowed
}

func (p *Planner) AddAction(a Action) {
	p.mu.Lock()
	defer p.mu.Unlock()
	name := a.Metadata().Name
	if p.done[name] {
		return
	}
	for _, existing := range p.actions {
		if existing.Metadata().Name == name {
			return
		}
	}
	p.actions = append(p.actions, a)
	sort.Slice(p.actions, func(i, j int) bool {
		return p.actions[i].Metadata().Priority < p.actions[j].Metadata().Priority
	})
}

// ActionRequirementsMet implements the capability gating for an action:
// ordinary actions run on any known capability (hints included — they may
// guide read-only same-target probing), while sensitive actions (credential
// brute force, uploads, session takeover) unlock only from verified-origin
// capabilities backed by executed evidence.
func ActionRequirementsMet(meta ActionMetadata, capMap map[string]bool, verifiedCapMap map[string]bool) bool {
	for _, req := range meta.Requires {
		if meta.Sensitive {
			if !verifiedCapMap[req] {
				return false
			}
		} else if !capMap[req] {
			return false
		}
	}
	return true
}

func (p *Planner) NextAction(kb *Knowledge) Action {
	p.mu.Lock()
	defer p.mu.Unlock()

	capMap, verifiedCapMap := p.capMaps(kb)

	for _, a := range p.actions {
		name := a.Metadata().Name
		if p.done[name] {
			continue
		}

		if a.Metadata().Destructive && !p.destructive {
			continue
		}

		if !ActionRequirementsMet(a.Metadata(), capMap, verifiedCapMap) {
			continue
		}

		p.done[name] = true
		return a
	}
	return nil
}

func (p *Planner) HasRemaining(kb *Knowledge) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	capMap, verifiedCapMap := p.capMaps(kb)

	for _, a := range p.actions {
		name := a.Metadata().Name
		if p.done[name] {
			continue
		}

		if a.Metadata().Destructive && !p.destructive {
			continue
		}

		if !ActionRequirementsMet(a.Metadata(), capMap, verifiedCapMap) {
			continue
		}
		return true
	}
	return false
}

// PendingDestructive lists consent-gated actions that are otherwise runnable
// right now. The report prints them so a withheld module never vanishes
// silently — the operator sees exactly what --destructive would unlock.
func (p *Planner) PendingDestructive(kb *Knowledge) []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.destructive {
		return nil
	}

	capMap, verifiedCapMap := p.capMaps(kb)

	var pending []string
	for _, a := range p.actions {
		meta := a.Metadata()
		if p.done[meta.Name] || !meta.Destructive {
			continue
		}
		if !ActionRequirementsMet(meta, capMap, verifiedCapMap) {
			continue
		}
		pending = append(pending, meta.Name)
	}
	return pending
}

func (p *Planner) capMaps(kb *Knowledge) (capMap, verifiedCapMap map[string]bool) {
	capMap = make(map[string]bool)
	verifiedCapMap = make(map[string]bool)
	for _, c := range kb.GetCapabilities() {
		capMap[c.Name] = true
		if c.Origin == OriginVerified {
			verifiedCapMap[c.Name] = true
		}
	}
	return capMap, verifiedCapMap
}
