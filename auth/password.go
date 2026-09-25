package auth

import (
	"errors"
	"strings"
)

func (s *Service) ChangePassword(userID, currentPassword, newPassword string) (string, User, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return "", User{}, errors.New("auth: user id is required")
	}
	if err := validatePassword(newPassword); err != nil {
		return "", User{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.loadLocked()
	if err != nil {
		return "", User{}, err
	}

	index := -1
	for i := range st.Users {
		if st.Users[i].ID == userID {
			index = i
			break
		}
	}
	if index < 0 {
		return "", User{}, errors.New("auth: user not found")
	}

	user := st.Users[index]
	if !verifyPassword(user.PasswordHash, currentPassword) {
		return "", User{}, errors.New("auth: current password is invalid")
	}

	hash, err := hashPassword(newPassword)
	if err != nil {
		return "", User{}, err
	}
	user.PasswordHash = hash
	st.Users[index] = user

	now := s.now().UTC()
	sessions := make([]Session, 0, len(st.Sessions))
	for _, session := range cleanSessions(st.Sessions, now) {
		if session.UserID != userID {
			sessions = append(sessions, session)
		}
	}

	token, err := randomToken(32)
	if err != nil {
		return "", User{}, err
	}
	sessions = append(sessions, Session{
		TokenHash: tokenHash(token),
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.sessionTTL),
	})
	st.Sessions = sessions

	if err := s.saveLocked(st); err != nil {
		return "", User{}, err
	}
	return token, publicUser(user), nil
}
