package oauth

import (
	"fmt"
	"sort"
	"strings"
)

// ListClients returns registered OAuth public clients without exposing token state.
func (s *Service) ListClients() ([]Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	items := make([]Client, len(st.Clients))
	for i := range st.Clients {
		items[i] = cloneClient(st.Clients[i])
	}
	sort.Slice(items, func(i, j int) bool {
		left, right := strings.ToLower(items[i].ClientName), strings.ToLower(items[j].ClientName)
		if left == right {
			return items[i].CreatedAt.Before(items[j].CreatedAt)
		}
		return left < right
	})
	return items, nil
}

// UpdateClient changes OAuth client metadata while preserving client_id.
// Existing authorization codes and tokens are revoked because redirect and
// grant semantics may have changed.
func (s *Service) UpdateClient(id string, metadata ClientMetadata) (Client, error) {
	id = strings.TrimSpace(id)
	normalized, err := normalizeClientMetadata(metadata)
	if err != nil {
		return Client{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return Client{}, err
	}

	index := -1
	for i := range st.Clients {
		if st.Clients[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return Client{}, fmt.Errorf("oauth: client %q not found", id)
	}

	current := st.Clients[index]
	current.ClientName = normalized.ClientName
	current.RedirectURIs = append([]string(nil), normalized.RedirectURIs...)
	current.GrantTypes = append([]string(nil), normalized.GrantTypes...)
	current.ResponseTypes = append([]string(nil), normalized.ResponseTypes...)
	st.Clients[index] = current
	st.Codes = removeClientCodes(st.Codes, id)
	st.Tokens = removeClientTokens(st.Tokens, id)

	if err := s.saveLocked(st); err != nil {
		return Client{}, err
	}
	return cloneClient(current), nil
}

// DeleteClient removes a client and revokes all authorization codes and token
// grants previously issued to it.
func (s *Service) DeleteClient(id string) error {
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.loadLocked()
	if err != nil {
		return err
	}
	index := -1
	for i := range st.Clients {
		if st.Clients[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("oauth: client %q not found", id)
	}
	st.Clients = append(st.Clients[:index], st.Clients[index+1:]...)
	st.Codes = removeClientCodes(st.Codes, id)
	st.Tokens = removeClientTokens(st.Tokens, id)
	return s.saveLocked(st)
}

func removeClientCodes(items []authorizationCode, clientID string) []authorizationCode {
	out := make([]authorizationCode, 0, len(items))
	for _, item := range items {
		if item.ClientID != clientID {
			out = append(out, item)
		}
	}
	return out
}

func removeClientTokens(items []tokenGrant, clientID string) []tokenGrant {
	out := make([]tokenGrant, 0, len(items))
	for _, item := range items {
		if item.ClientID != clientID {
			out = append(out, item)
		}
	}
	return out
}
