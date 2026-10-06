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
