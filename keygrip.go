package keygrip

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"sync"
)

const (
	addKey    = "add"
	removeKey = "remove"
)

type (
	// Keygrip keygrip struct
	Keygrip struct {
		Keys [][]byte
		sync.RWMutex
	}
)

func sign(data, key []byte) string {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	s := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(s)
}

// Sign get the sign of data
func (kg *Keygrip) Sign(data string) string {
	kg.RLock()
	defer kg.RUnlock()
	return sign([]byte(data), kg.Keys[0])
}

// index get the valid index of key
func (kg *Keygrip) index(data, digest string) int {
	result := -1
	d := []byte(data)
	for index, key := range kg.Keys {
		if sign(d, key) == digest {
			result = index
		}
	}
	return result
}

// Verify verify the data is valid
func (kg *Keygrip) Verify(data, digest string) bool {
	kg.RLock()
	defer kg.RUnlock()
	return kg.index(data, digest) > -1
}

// handleKey do something for keys
func (kg *Keygrip) handleKey(key, t string) {
	if key == "" {
		return
	}
	kg.Lock()
	defer kg.Unlock()
	newKey := []byte(key)
	keys := kg.Keys
	index := -1
	for i, k := range keys {
		if bytes.Equal(newKey, k) {
			index = i
		}
	}
	if t == addKey {
		// the key exists
		if index != -1 {
			return
		}
		kg.Keys = append([][]byte{
			newKey,
		}, keys...)
	} else {
		// the key not exists
		if index == -1 {
			return
		}
		kg.Keys = append(keys[0:index], keys[index+1:]...)
	}
}

// AddKey add key for hash
func (kg *Keygrip) AddKey(key string) {
	kg.handleKey(key, addKey)
}

// RemoveKey remove key for hash
func (kg *Keygrip) RemoveKey(key string) {
	kg.handleKey(key, removeKey)
}

// New Create a new keygrip
func New(keys []string) *Keygrip {
	arr := make([][]byte, 0)
	for _, k := range keys {
		arr = append(arr, []byte(k))
	}
	return &Keygrip{
		Keys: arr,
	}
}
