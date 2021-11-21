package keygrip

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
)

type (
	// Keygrip keygrip struct
	Keygrip struct {
		mutex *sync.RWMutex
		keys  [][]byte
	}
)

func sign(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// Sign returns the sign data using the first key
func (kg *Keygrip) Sign(data []byte) []byte {
	if kg.mutex != nil {
		kg.mutex.RLock()
		defer kg.mutex.RUnlock()
	}
	var key []byte
	if len(kg.keys) != 0 {
		key = kg.keys[0]
	}
	src := sign(data, key)
	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(src)))
	base64.RawURLEncoding.Encode(dst, src)
	return dst
}

func (kg *Keygrip) index(data, digest []byte) int {
	result := -1
	dig := make([]byte, base64.RawURLEncoding.DecodedLen(len(digest)))
	_, err := base64.RawURLEncoding.Decode(dig, digest)
	// 如果出错则返回-2
	if err != nil {
		return -2
	}
	for index, key := range kg.keys {
		if bytes.Equal(sign(data, key), dig) {
			result = index
			break
		}
	}
	return result
}

// Index returns the index of the key which match digest.
// It will return -2 if the digest isn't raw url encoding.
// It will return -1 if no match key for the digest.
func (kg *Keygrip) Index(data, digest []byte) int {
	if kg.mutex != nil {
		kg.mutex.RLock()
		defer kg.mutex.RUnlock()
	}
	return kg.index(data, digest)
}

// Verify returns true if the disgest is created by keygrip
func (kg *Keygrip) Verify(data, digest []byte) bool {
	if kg.mutex != nil {
		kg.mutex.RLock()
		defer kg.mutex.RUnlock()
	}
	return kg.index(data, digest) > -1
}

func contains(arr [][]byte, value []byte) bool {
	for _, v := range arr {
		if bytes.Equal(v, value) {
			return true
		}
	}
	return false
}

// AddKey adds the key to keygrip
func (kg *Keygrip) AddKey(key string) {
	if kg.mutex != nil {
		kg.mutex.Lock()
		defer kg.mutex.Unlock()
	}
	k := []byte(key)
	// 如果已存在
	if contains(kg.keys, k) {
		return
	}
	// 新增加的key放在数组最前，优先使用
	kg.keys = append([][]byte{
		k,
	}, kg.keys...)
}

// RemoveKey removes the key from keygrip
func (kg *Keygrip) RemoveKey(key string) {
	if kg.mutex != nil {
		kg.mutex.Lock()
		defer kg.mutex.Unlock()
	}
	k := []byte(key)
	keys := make([][]byte, 0, len(kg.keys))
	for _, key := range kg.keys {
		if bytes.Equal(k, key) {
			continue
		}
		keys = append(keys, key)
	}
	kg.keys = keys
}

func (kg *Keygrip) setKeys(keys []string) {
	arr := make([][]byte, 0)
	for _, k := range keys {
		arr = append(arr, []byte(k))
	}
	kg.keys = arr
}

// SetKeys sets the keys of keygrip
func (kg *Keygrip) SetKeys(keys []string) {
	if kg.mutex != nil {
		kg.mutex.Lock()
		defer kg.mutex.Unlock()
	}
	kg.setKeys(keys)
}

// Keys returns the key list of keygrip
func (kg *Keygrip) Keys() []string {
	if kg.mutex != nil {
		kg.mutex.RLock()
		defer kg.mutex.RUnlock()
	}
	keys := kg.keys
	result := make([]string, len(keys))
	for i, v := range keys {
		result[i] = string(v)
	}
	return result
}

// New returns a new keygrip
func New(keys []string) *Keygrip {
	if len(keys) == 0 {
		panic(errors.New("keys can not be empty"))
	}
	kg := &Keygrip{}
	kg.setKeys(keys)
	return kg
}

// NewRWMutex returns a new keygrip with rw mutex
func NewRWMutex(keys []string) *Keygrip {
	kg := New(keys)
	kg.mutex = &sync.RWMutex{}
	return kg
}
