package auth

import (
	"path/filepath"
	"testing"
)

func TestChangePasswordInvalidatesOldSessionsAndReturnsFreshSession(t *testing.T) {
	svc, err := New(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	user, err := svc.BootstrapAdmin("admin", "old-password-123")
	if err != nil {
		t.Fatal(err)
	}
	firstToken, _, err := svc.Login("admin", "old-password-123")
	if err != nil {
		t.Fatal(err)
	}
	secondToken, _, err := svc.Login("admin", "old-password-123")
	if err != nil {
		t.Fatal(err)
	}

	freshToken, changed, err := svc.ChangePassword(user.ID, "old-password-123", "new-password-456")
	if err != nil {
		t.Fatal(err)
	}
	if freshToken == "" || changed.ID != user.ID || changed.PasswordHash != "" {
		t.Fatalf("unexpected change result: token=%q user=%#v", freshToken, changed)
	}
	if _, err := svc.Authenticate(firstToken); err == nil {
		t.Fatal("first old session should be invalid")
	}
	if _, err := svc.Authenticate(secondToken); err == nil {
		t.Fatal("second old session should be invalid")
	}
	if got, err := svc.Authenticate(freshToken); err != nil || got.ID != user.ID {
		t.Fatalf("fresh session invalid: user=%#v err=%v", got, err)
	}
	if _, _, err := svc.Login("admin", "old-password-123"); err == nil {
		t.Fatal("old password should no longer authenticate")
	}
	if _, got, err := svc.Login("admin", "new-password-456"); err != nil || got.ID != user.ID {
		t.Fatalf("new password login failed: user=%#v err=%v", got, err)
	}
}

func TestChangePasswordValidatesCurrentAndNewPassword(t *testing.T) {
	svc, err := New(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	user, err := svc.BootstrapAdmin("admin", "old-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ChangePassword(user.ID, "wrong-password", "new-password-456"); err == nil {
		t.Fatal("expected current password validation error")
	}
	if _, _, err := svc.ChangePassword(user.ID, "old-password-123", "short"); err == nil {
		t.Fatal("expected new password length validation error")
	}
}
