package auth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/google/uuid"
)

func TestDelegationExpiresOn(t *testing.T) {
	cases := []struct {
		created, lastUsed, want string
	}{
		{"2026-01-01", "", "2026-03-02"},           // unused: 60 days after creation
		{"2026-01-01", "2026-06-01", "2026-07-31"}, // idle window slides with use
		{"2026-01-01", "2026-12-20", "2027-01-01"}, // capped at one year from creation
	}
	for _, c := range cases {
		d := &db.Delegation{CreatedAt: c.created}
		if c.lastUsed != "" {
			d.LastUsedAt = sql.NullString{String: c.lastUsed, Valid: true}
		}
		if got := d.ExpiresOn(); got != c.want {
			t.Errorf("created %s, last used %q: ExpiresOn = %s, want %s", c.created, c.lastUsed, got, c.want)
		}
	}
	d := &db.Delegation{CreatedAt: "2026-01-01"}
	if d.Expired(time.Date(2026, 3, 2, 23, 0, 0, 0, time.UTC)) || !d.Expired(time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)) {
		t.Error("expiry boundary: last valid day should be the ExpiresOn date itself")
	}
}

func TestRefreshRejectsExpiredDelegation(t *testing.T) {
	e := newTestEnv(t)
	refresh := func(token string) int {
		b, _ := json.Marshal(map[string]string{"refresh_token": token})
		rec := httptest.NewRecorder()
		e.h.RefreshDelegationToken(rec, httptest.NewRequest(http.MethodPost, "/refresh", bytes.NewReader(b)))
		return rec.Code
	}
	insert := func(token, created, lastUsed string) string {
		id := uuid.New().String()
		var lu any
		if lastUsed != "" {
			lu = lastUsed
		}
		if _, err := e.db.Exec(`INSERT INTO delegations (id, user_id, client_name, client_url, scope, refresh_token_hash, created_at, last_used_at)
			VALUES (?, ?, 'app', 'https://app', 'upload', ?, ?, ?)`, id, e.userID, db.HashRefreshToken(token), created, lu); err != nil {
			t.Fatal(err)
		}
		return id
	}
	today := time.Now().UTC()
	fmtDay := func(d time.Time) string { return d.Format(db.DelegationTimeFormat) }

	insert("fresh", fmtDay(today.AddDate(0, 0, -10)), "")
	if code := refresh("fresh"); code != http.StatusOK {
		t.Fatalf("fresh delegation refused: %d", code)
	}
	idle := insert("idle", fmtDay(today.AddDate(0, 0, -200)), fmtDay(today.AddDate(0, 0, -61)))
	if code := refresh("idle"); code != http.StatusUnauthorized {
		t.Fatalf("idle delegation accepted: %d", code)
	}
	if ok, _ := db.DelegationExists(e.db, idle, e.userID); ok {
		t.Error("expired delegation not deleted on refresh")
	}
	insert("old", fmtDay(today.AddDate(-1, 0, -2)), fmtDay(today))
	if code := refresh("old"); code != http.StatusUnauthorized {
		t.Fatalf("delegation past maximum lifetime accepted: %d", code)
	}

	// The periodic sweep removes expired rows too (and so kills their access tokens).
	stale := insert("stale", fmtDay(today.AddDate(0, 0, -90)), "")
	if err := db.PruneExpiredDelegations(e.db, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := db.DelegationExists(e.db, stale, e.userID); ok {
		t.Error("sweep kept an expired delegation")
	}
	if code := refresh("fresh"); code != http.StatusOK {
		t.Errorf("sweep removed a live delegation: %d", code)
	}
}
