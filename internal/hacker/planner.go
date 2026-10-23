package hacker

import (
	"sort"
	"sync"
)

type Planner struct {
	mu      sync.Mutex
	actions []Action
	done    map[string]bool
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

	caps := kb.GetCapabilities()
	capMap := make(map[string]bool)
	verifiedCapMap := make(map[string]bool)
	for _, c := range caps {
		capMap[c.Name] = true
		if c.Origin == OriginVerified {
			verifiedCapMap[c.Name] = true
		}
	}

	for _, a := range p.actions {
		name := a.Metadata().Name
		if p.done[name] {
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

	caps := kb.GetCapabilities()
	capMap := make(map[string]bool)
	verifiedCapMap := make(map[string]bool)
	for _, c := range caps {
		capMap[c.Name] = true
		if c.Origin == OriginVerified {
			verifiedCapMap[c.Name] = true
		}
	}

	for _, a := range p.actions {
		name := a.Metadata().Name
		if p.done[name] {
			continue
		}

		if !ActionRequirementsMet(a.Metadata(), capMap, verifiedCapMap) {
			continue
		}
		return true
	}
	return false
}
