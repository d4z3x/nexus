package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/d4z3x/nexus/internal/adguard"
	"github.com/d4z3x/nexus/internal/db"
)

type ReplicaStatus struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Mode    string `json:"mode"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Added   int    `json:"added"`
	Removed int    `json:"removed"`
}

type Status struct {
	LastSync        time.Time         `json:"last_sync"`
	NextSync        time.Time         `json:"next_sync"`
	Running         bool              `json:"running"`
	Success         bool              `json:"success"`
	Error           string            `json:"error,omitempty"`
	PrimaryCount    int               `json:"primary_count"`
	FlattenCNAMEs   bool              `json:"flatten_cnames"`
	PrimaryURL      string            `json:"primary_url"`
	SyncInterval    int               `json:"sync_interval"`
	PrimaryRewrites []adguard.Rewrite `json:"primary_rewrites"`
	Replicas        []ReplicaStatus   `json:"replicas"`
}

type SyncEngine struct {
	primary       *adguard.Client
	database      *db.DB
	interval      time.Duration
	flattenCNAMEs bool
	primaryURL    string

	mu         sync.RWMutex
	status     Status
	cancel     context.CancelFunc
	resetTimer chan time.Duration
}

func NewSyncEngine(primary *adguard.Client, database *db.DB, interval time.Duration, flattenCNAMEs bool, primaryURL string) *SyncEngine {
	return &SyncEngine{
		primary:       primary,
		database:      database,
		interval:      interval,
		flattenCNAMEs: flattenCNAMEs,
		primaryURL:    primaryURL,
		resetTimer:    make(chan time.Duration, 1),
		status: Status{
			FlattenCNAMEs: flattenCNAMEs,
			PrimaryURL:    primaryURL,
			SyncInterval:  int(interval.Seconds()),
		},
	}
}

func (e *SyncEngine) Start(ctx context.Context) {
	ctx, e.cancel = context.WithCancel(ctx)

	go func() {
		// Run initial sync without blocking server startup
		e.RunSync()

		ticker := time.NewTicker(e.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case newInterval := <-e.resetTimer:
				ticker.Reset(newInterval)
			case <-ticker.C:
				e.RunSync()
			}
		}
	}()
}

func (e *SyncEngine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
}

func (e *SyncEngine) SetInterval(d time.Duration) {
	e.mu.Lock()
	e.interval = d
	e.status.SyncInterval = int(d.Seconds())
	e.status.NextSync = time.Now().Add(d)
	e.mu.Unlock()

	e.resetTimer <- d
	log.Printf("[sync] interval updated to %ds", int(d.Seconds()))
}

func (e *SyncEngine) GetStatus() Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.status
}

func (e *SyncEngine) RunSync() {
	e.mu.Lock()
	e.status.Running = true
	e.mu.Unlock()

	var syncErr error
	var primaryRewrites []adguard.Rewrite
	var replicaStatuses []ReplicaStatus

	defer func() {
		e.mu.Lock()
		e.status.Running = false
		e.status.LastSync = time.Now()
		e.status.NextSync = time.Now().Add(e.interval)
		e.status.PrimaryCount = len(primaryRewrites)
		e.status.PrimaryRewrites = primaryRewrites
		e.status.Replicas = replicaStatuses
		if syncErr != nil {
			e.status.Success = false
			e.status.Error = syncErr.Error()
		} else {
			e.status.Success = true
			e.status.Error = ""
		}
		e.mu.Unlock()
	}()

	log.Println("[sync] starting sync...")

	primaryRewrites, syncErr = e.primary.ListRewrites()
	if syncErr != nil {
		log.Printf("[sync] error listing primary rewrites: %v", syncErr)
		return
	}
	log.Printf("[sync] found %d rewrites on primary", len(primaryRewrites))

	targetRewrites := primaryRewrites
	if e.flattenCNAMEs {
		targetRewrites = flattenCNAMERecords(primaryRewrites)
	}

	var primaryFiltering *adguard.FilteringStatus
	primaryFiltering, _ = e.primary.GetFilteringStatus()

	replicas, err := e.database.ListReplicas()
	if err != nil {
		syncErr = fmt.Errorf("list replicas: %w", err)
		return
	}

	allSuccess := true
	for _, replica := range replicas {
		rs := ReplicaStatus{
			ID:   replica.ID,
			Name: replica.Name,
			URL:  replica.URL,
			Mode: replica.Mode,
		}

		client := adguard.NewClient(replica.URL, replica.Username, replica.Password)

		var replicaErr error
		switch replica.Mode {
		case "rewrites":
			rs.Added, rs.Removed, replicaErr = syncRewrites(client, targetRewrites)
		case "blocklist":
			rs.Added, rs.Removed, replicaErr = syncBlocklists(client, primaryFiltering)
		case "full":
			a1, r1, err1 := syncRewrites(client, targetRewrites)
			a2, r2, err2 := syncBlocklists(client, primaryFiltering)
			rs.Added = a1 + a2
			rs.Removed = r1 + r2
			if err1 != nil {
				replicaErr = err1
			} else if err2 != nil {
				replicaErr = err2
			}
		default:
			replicaErr = fmt.Errorf("unknown sync mode: %s", replica.Mode)
		}

		if replicaErr != nil {
			rs.Success = false
			rs.Error = replicaErr.Error()
			allSuccess = false
			log.Printf("[sync] replica %s (%s) failed: %v", replica.Name, replica.URL, replicaErr)
		} else {
			rs.Success = true
			log.Printf("[sync] replica %s (%s) synced: +%d -%d", replica.Name, replica.URL, rs.Added, rs.Removed)
		}

		replicaStatuses = append(replicaStatuses, rs)
	}

	if !allSuccess {
		syncErr = fmt.Errorf("one or more replicas failed")
	}

	log.Printf("[sync] complete across %d replica(s)", len(replicas))
}

func syncRewrites(dest *adguard.Client, targetRewrites []adguard.Rewrite) (added, removed int, err error) {
	destRewrites, err := dest.ListRewrites()
	if err != nil {
		return 0, 0, fmt.Errorf("list dest rewrites: %w", err)
	}

	targetSet := make(map[string]struct{})
	for _, r := range targetRewrites {
		targetSet[rewriteKey(r)] = struct{}{}
	}

	destSet := make(map[string]struct{})
	for _, r := range destRewrites {
		destSet[rewriteKey(r)] = struct{}{}
	}

	for _, r := range targetRewrites {
		if _, exists := destSet[rewriteKey(r)]; !exists {
			if e := dest.AddRewrite(r); e != nil {
				return added, removed, fmt.Errorf("add rewrite: %w", e)
			}
			added++
		}
	}

	for _, r := range destRewrites {
		if _, exists := targetSet[rewriteKey(r)]; !exists {
			if e := dest.DeleteRewrite(r); e != nil {
				return added, removed, fmt.Errorf("delete rewrite: %w", e)
			}
			removed++
		}
	}

	return added, removed, nil
}

func syncBlocklists(dest *adguard.Client, primaryFiltering *adguard.FilteringStatus) (added, removed int, err error) {
	if primaryFiltering == nil {
		return 0, 0, nil
	}

	destFiltering, err := dest.GetFilteringStatus()
	if err != nil {
		return 0, 0, fmt.Errorf("get dest filtering status: %w", err)
	}

	a, r, e := syncFilterList(dest, primaryFiltering.Filters, destFiltering.Filters, false)
	added += a
	removed += r
	if e != nil {
		return added, removed, e
	}

	a, r, e = syncFilterList(dest, primaryFiltering.WhitelistFilters, destFiltering.WhitelistFilters, true)
	added += a
	removed += r
	if e != nil {
		return added, removed, e
	}

	if err := dest.SetUserRules(primaryFiltering.UserRules); err != nil {
		return added, removed, fmt.Errorf("set user rules: %w", err)
	}

	return added, removed, nil
}

func syncFilterList(dest *adguard.Client, primary, destFilters []adguard.Filter, whitelist bool) (added, removed int, err error) {
	primaryURLs := make(map[string]adguard.Filter)
	for _, f := range primary {
		primaryURLs[f.URL] = f
	}

	destURLs := make(map[string]adguard.Filter)
	for _, f := range destFilters {
		destURLs[f.URL] = f
	}

	for url, f := range primaryURLs {
		if _, exists := destURLs[url]; !exists {
			if e := dest.AddFilter(f.Name, f.URL, whitelist); e != nil {
				return added, removed, e
			}
			added++
		}
	}

	for url := range destURLs {
		if _, exists := primaryURLs[url]; !exists {
			if e := dest.RemoveFilter(url, whitelist); e != nil {
				return added, removed, e
			}
			removed++
		}
	}

	return added, removed, nil
}

func rewriteKey(r adguard.Rewrite) string {
	return r.Domain + "|" + r.Answer
}

func flattenCNAMERecords(rewrites []adguard.Rewrite) []adguard.Rewrite {
	var result []adguard.Rewrite
	for _, r := range rewrites {
		if isCNAME(r.Answer) {
			resolved := resolveCNAME(r.Answer)
			for _, ip := range resolved {
				result = append(result, adguard.Rewrite{
					Domain: r.Domain,
					Answer: ip,
				})
			}
			if len(resolved) == 0 {
				log.Printf("[sync] warning: could not flatten CNAME %s for %s, keeping original", r.Answer, r.Domain)
				result = append(result, r)
			}
		} else {
			result = append(result, r)
		}
	}
	return result
}

func isCNAME(answer string) bool {
	if net.ParseIP(answer) != nil {
		return false
	}
	if strings.HasPrefix(answer, "|") || strings.HasPrefix(answer, "!") {
		return false
	}
	return true
}

func resolveCNAME(hostname string) []string {
	ips, err := net.LookupHost(hostname)
	if err != nil {
		log.Printf("[sync] failed to resolve %s: %v", hostname, err)
		return nil
	}
	return ips
}
