package oauth

import (
	"errors"
	"strings"
)

// RevokeToken invalidates the token grant identified by either an access token
// or refresh token. Unknown tokens are treated as already revoked. A token
// issued to a different client cannot be revoked by the caller.
func (s *Service) RevokeToken(clientID, token string) error {
	clientID = strings.TrimSpace(clientID)
	token = strings.TrimSpace(token)
	if clientID == "" {
		return errors.New("oauth: client_id is required")
	}
	if token == "" {
		return errors.New("oauth: token is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.loadLocked()
	if err != nil {
		return err
	}
	clientExists := false
	for _, client := range st.Clients {
		if client.ID == clientID {
			clientExists = true
			break
		}
	}
	if !clientExists {
		return errors.New("oauth: client is invalid")
	}

	hash := tokenHash(token)
	index := -1
	for i, grant := range st.Tokens {
		if grant.AccessHash == hash || grant.RefreshHash == hash {
			if grant.ClientID != clientID {
				return errors.New("oauth: token does not belong to client")
			}
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	st.Tokens = append(st.Tokens[:index], st.Tokens[index+1:]...)
	return s.saveLocked(st)
}
