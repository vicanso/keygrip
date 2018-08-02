package keygrip

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"sync"
)

const (
	addKey    = "add"
	removeKey = "remove"
)

type (
	// Keygrip keygrip struct
	Keygrip struct {
		keys [][]byte
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
	return sign([]byte(data), kg.keys[0])
}

// Index get the valid index of key
func (kg *Keygrip) Index(data, digest string) int {
	result := -1
	d := []byte(data)
	for index, key := range kg.keys {
		if result == -1 && sign(d, key) == digest {
			result = index
		}
	}
	return result
}

// Verify verify the data is valid
func (kg *Keygrip) Verify(data, digest string) bool {
	kg.RLock()
	defer kg.RUnlock()
	return kg.Index(data, digest) > -1
}

// handleKey do something for keys
func (kg *Keygrip) handleKey(key, t string) {
	if key == "" {
		return
	}
	kg.Lock()
	defer kg.Unlock()
	newKey := []byte(key)
	keys := kg.keys
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
		kg.keys = append([][]byte{
			newKey,
		}, keys...)
	} else {
		// the key not exists
		if index == -1 {
			return
		}
		kg.keys = append(keys[0:index], keys[index+1:]...)
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

// RemoveAllKeys remove all keys
func (kg *Keygrip) RemoveAllKeys() {
	kg.Lock()
	defer kg.Unlock()
	kg.keys = kg.keys[0:0]
}

// Keys get the key of keygrip
func (kg *Keygrip) Keys() []string {
	kg.RLock()
	defer kg.RUnlock()
	result := make([]string, len(kg.keys))
	for i, v := range kg.keys {
		result[i] = string(v)
	}
	return result
}

// New Create a new keygrip
func New(keys []string) *Keygrip {
	if len(keys) == 0 {
		panic(errors.New("keys can not be empty"))
	}
	arr := make([][]byte, 0)
	for _, k := range keys {
		arr = append(arr, []byte(k))
	}
	return &Keygrip{
		keys: arr,
	}
}
