package main

import (
	"encoding/json"
	"testing"
)

func TestPlayLoadUnmarshalLobbyBypass(t *testing.T) {
	config.NameKey = "name"
	config.LobbyBypassKey = "lobby_bypass"

	tests := []struct {
		name string
		body string
		want bool
	}{
		{"boolean true", `{"sub":"1","lobby_bypass":true}`, true},
		{"boolean false", `{"sub":"1","lobby_bypass":false}`, false},
		{"string true", `{"sub":"1","lobby_bypass":"true"}`, true},
		{"string false", `{"sub":"1","lobby_bypass":"false"}`, false},
		{"unrelated string", `{"sub":"1","lobby_bypass":"yes"}`, false},
		{"claim absent", `{"sub":"1"}`, false},
		{"wrong type", `{"sub":"1","lobby_bypass":1}`, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var p PlayLoad
			if err := json.Unmarshal([]byte(tc.body), &p); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if p.LobbyBypass != tc.want {
				t.Errorf("LobbyBypass = %v, want %v", p.LobbyBypass, tc.want)
			}
		})
	}
}

func TestPlayLoadUnmarshalCustomClaimKey(t *testing.T) {
	config.NameKey = "name"
	config.LobbyBypassKey = "skip_lobby"

	var p PlayLoad
	if err := json.Unmarshal([]byte(`{"sub":"1","skip_lobby":true,"lobby_bypass":false}`), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !p.LobbyBypass {
		t.Error("configured claim key was not honoured")
	}
}

// The field is omitted when false, so a deployment that does not use the
// feature emits exactly the token it emitted before.
func TestUserContextOmitsLobbyBypassWhenFalse(t *testing.T) {
	u := &UserContext{}
	u.User.Email = "a@b.de"
	u.User.Name = "A B"

	b, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(b), `{"user":{"email":"a@b.de","name":"A B"}}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}

	u.User.LobbyBypass = true
	b, err = json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(b), `{"user":{"email":"a@b.de","name":"A B","lobby_bypass":true}}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func mustPlayLoad(t *testing.T, body string) PlayLoad {
	t.Helper()
	var p PlayLoad
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return p
}

// Some IdPs deliver custom claims only via UserInfo.
func TestMergeUserInfo(t *testing.T) {
	config.NameKey = "name"
	config.LobbyBypassKey = "lobby_bypass"

	tests := []struct {
		name     string
		id, info string
		want     bool
	}{
		{"claim only in UserInfo", `{"sub":"1"}`, `{"lobby_bypass":true}`, true},
		{"ID token true wins", `{"lobby_bypass":true}`, `{"lobby_bypass":false}`, true},
		{"ID token explicit false wins", `{"lobby_bypass":false}`, `{"lobby_bypass":true}`, false},
		{"absent everywhere", `{"sub":"1"}`, `{}`, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := mustPlayLoad(t, tc.id)
			p.mergeUserInfo(mustPlayLoad(t, tc.info))
			if p.LobbyBypass != tc.want {
				t.Errorf("LobbyBypass = %v, want %v", p.LobbyBypass, tc.want)
			}
		})
	}

	p := mustPlayLoad(t, `{"name":"ID","email":"id@b.de"}`)
	p.mergeUserInfo(mustPlayLoad(t, `{"name":"Info","email":"info@b.de"}`))
	if p.Name != "ID" || p.Email != "id@b.de" {
		t.Errorf("ID token name/email overwritten: %+v", p)
	}
}

func TestNeedsUserInfo(t *testing.T) {
	config.NameKey = "name"

	tests := []struct {
		name, key, body string
		want            bool
	}{
		{"feature off, complete", "", `{"name":"A","email":"a@b.de"}`, false},
		{"feature off, email missing", "", `{"name":"A"}`, true},
		{"feature on, claim present", "lobby_bypass", `{"name":"A","email":"a@b.de","lobby_bypass":false}`, false},
		{"feature on, claim absent", "lobby_bypass", `{"name":"A","email":"a@b.de"}`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config.LobbyBypassKey = tc.key
			if got := mustPlayLoad(t, tc.body).needsUserInfo(); got != tc.want {
				t.Errorf("needsUserInfo = %v, want %v", got, tc.want)
			}
		})
	}
}

// Without LOBBY_BYPASS_KEY the claim is ignored, even if the IdP sends it.
func TestLobbyBypassDisabledByDefault(t *testing.T) {
	config.NameKey = "name"
	config.LobbyBypassKey = ""

	if mustPlayLoad(t, `{"sub":"1","lobby_bypass":true}`).LobbyBypass {
		t.Error("claim honoured although LOBBY_BYPASS_KEY is unset")
	}
}
