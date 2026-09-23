package auth

import (
	"path/filepath"
	"testing"
)

func TestBootstrapAndLogin(t *testing.T) {
	service, err := New(filepath.Join(t.TempDir(), "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	needed, err := service.NeedsBootstrap()
	if err != nil || !needed {
		t.Fatalf("bootstrap status: %v %v", needed, err)
	}
	user, err := service.BootstrapAdmin("admin", "very-strong-password")
	if err != nil || user.Role != "admin" || user.PasswordHash != "" {
		t.Fatalf("bootstrap: %#v %v", user, err)
	}
	if _, err := service.BootstrapAdmin("other", "another-strong-password"); err == nil {
		t.Fatal("expected bootstrap to close after first admin")
	}
	token, loggedIn, err := service.Login("admin", "very-strong-password")
	if err != nil || token == "" || loggedIn.ID != user.ID {
		t.Fatalf("login: %#v %v", loggedIn, err)
	}
	if _, err := service.Authenticate(token); err != nil {
		t.Fatal(err)
	}
	if err := service.Logout(token); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(token); err == nil {
		t.Fatal("expected logged out session to fail")
	}
}
