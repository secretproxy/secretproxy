package app

import (
	lru "github.com/hashicorp/golang-lru/v2"
)

type Vault struct {
	secrets *lru.Cache[string, string] // placeholder -> real value
	seen    *lru.Cache[string, bool]   // already logged
}

func NewVault(size int) *Vault {
	if size <= 0 {
		size = 2048
	}
	secrets, _ := lru.New[string, string](size)
	seen, _ := lru.New[string, bool](size)
	return &Vault{secrets: secrets, seen: seen}
}

func (v *Vault) Count() int {
	if v == nil {
		return 0
	}
	return v.secrets.Len()
}

// Store returns true if this is a new secret.
func (v *Vault) Store(placeholder, secret string) bool {
	_, existed := v.seen.Get(placeholder)
	v.secrets.Add(placeholder, secret)
	v.seen.Add(placeholder, true)
	return !existed
}

func (v *Vault) Get(placeholder string) (string, bool) {
	return v.secrets.Get(placeholder)
}
