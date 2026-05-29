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

func (p *Planner) NextAction(kb *Knowledge) Action {
	p.mu.Lock()
	defer p.mu.Unlock()

	caps := kb.GetCapabilities()
	capMap := make(map[string]bool)
	for _, c := range caps {
		capMap[c.Name] = true
	}

	for _, a := range p.actions {
		name := a.Metadata().Name
		if p.done[name] {
			continue
		}

		reqs := a.Metadata().Requires
		if len(reqs) > 0 {
			allMet := true
			for _, req := range reqs {
				if !capMap[req] {
					allMet = false
					break
				}
			}
			if !allMet {
				continue
			}
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
	for _, c := range caps {
		capMap[c.Name] = true
	}

	for _, a := range p.actions {
		name := a.Metadata().Name
		if p.done[name] {
			continue
		}

		reqs := a.Metadata().Requires
		if len(reqs) == 0 {
			return true
		}

		allMet := true
		for _, req := range reqs {
			if !capMap[req] {
				allMet = false
				break
			}
		}
		if allMet {
			return true
		}
	}
	return false
}
