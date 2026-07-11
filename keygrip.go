package keygrip

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"hash"
	"sync"
)

type (
	// Keygrip keygrip struct
	Keygrip struct {
		mutex *sync.RWMutex
		keys  [][]byte
		// pools holds one sync.Pool per key for reusable HMAC-SHA256 instances.
		// hash.Hash is not safe for concurrent use, so each Get/Put cycle is exclusive.
		pools []*sync.Pool
	}
)

var errEmptyKeys = errors.New("keys can not be empty")

// sign computes HMAC-SHA256(data, key) and returns a newly allocated digest.
func sign(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	return h.Sum(make([]byte, 0, sha256.Size))
}

// signAt computes HMAC-SHA256 of data with the key at index i into dst.
// dst must have capacity >= sha256.Size. Uses a per-key pool of hash.Hash.
func (kg *Keygrip) signAt(i int, dst, data []byte) []byte {
	h := kg.pools[i].Get().(hash.Hash)
	h.Reset()
	_, _ = h.Write(data)
	sum := h.Sum(dst[:0])
	kg.pools[i].Put(h)
	return sum
}

func (kg *Keygrip) rebuildPools() {
	pools := make([]*sync.Pool, len(kg.keys))
	for i := range kg.keys {
		key := kg.keys[i]
		pools[i] = &sync.Pool{
			New: func() any {
				return hmac.New(sha256.New, key)
			},
		}
	}
	kg.pools = pools
}

// Sign returns the base64.RawURLEncoding digest using the first key.
func (kg *Keygrip) Sign(data []byte) []byte {
	if kg.mutex != nil {
		kg.mutex.RLock()
		defer kg.mutex.RUnlock()
	}
	if len(kg.keys) == 0 {
		panic(errEmptyKeys)
	}
	var sum [sha256.Size]byte
	src := kg.signAt(0, sum[:], data)
	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(src)))
	base64.RawURLEncoding.Encode(dst, src)
	return dst
}

func (kg *Keygrip) index(data, digest []byte) int {
	dig := make([]byte, base64.RawURLEncoding.DecodedLen(len(digest)))
	n, err := base64.RawURLEncoding.Decode(dig, digest)
	// Invalid encoding → -2 (API contract).
	if err != nil {
		return -2
	}
	// HMAC-SHA256 digest is always sha256.Size bytes; wrong length never matches.
	if n != sha256.Size {
		return -1
	}
	dig = dig[:n]

	for i := range kg.keys {
		var sum [sha256.Size]byte
		// Constant-time compare to avoid leaking MAC bytes via timing.
		if hmac.Equal(kg.signAt(i, sum[:], data), dig) {
			return i
		}
	}
	return -1
}

// Index returns the index of the key which matches digest.
// It returns -2 if the digest is not valid base64.RawURLEncoding.
// It returns -1 if no key matches the digest (including wrong-length digests).
func (kg *Keygrip) Index(data, digest []byte) int {
	if kg.mutex != nil {
		kg.mutex.RLock()
		defer kg.mutex.RUnlock()
	}
	return kg.index(data, digest)
}

// Verify returns true if the digest was created by one of the current keys.
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

// AddKey adds the key to the front of the key list (preferred for signing).
// If the key already exists, this is a no-op.
func (kg *Keygrip) AddKey(key string) {
	if kg.mutex != nil {
		kg.mutex.Lock()
		defer kg.mutex.Unlock()
	}
	k := []byte(key)
	if contains(kg.keys, k) {
		return
	}
	// Insert at front: grow once, shift in place.
	kg.keys = append(kg.keys, nil)
	copy(kg.keys[1:], kg.keys)
	kg.keys[0] = k
	kg.rebuildPools()
}

// RemoveKey removes the key from the key list. Missing keys are ignored.
// The last remaining key is never removed (no-op) so Sign always has a credential.
func (kg *Keygrip) RemoveKey(key string) {
	if kg.mutex != nil {
		kg.mutex.Lock()
		defer kg.mutex.Unlock()
	}
	if len(kg.keys) <= 1 {
		return
	}
	k := []byte(key)
	for i, existing := range kg.keys {
		if bytes.Equal(k, existing) {
			copy(kg.keys[i:], kg.keys[i+1:])
			kg.keys[len(kg.keys)-1] = nil
			kg.keys = kg.keys[:len(kg.keys)-1]
			kg.rebuildPools()
			return
		}
	}
}

func (kg *Keygrip) setKeys(keys []string) {
	if len(keys) == 0 {
		panic(errEmptyKeys)
	}
	arr := make([][]byte, len(keys))
	for i, k := range keys {
		arr[i] = []byte(k)
	}
	kg.keys = arr
	kg.rebuildPools()
}

// SetKeys replaces the entire key list. keys must not be empty.
func (kg *Keygrip) SetKeys(keys []string) {
	if kg.mutex != nil {
		kg.mutex.Lock()
		defer kg.mutex.Unlock()
	}
	kg.setKeys(keys)
}

// Keys returns a copy of the current key list as strings.
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

// New returns a new keygrip. keys must not be empty.
func New(keys []string) *Keygrip {
	if len(keys) == 0 {
		panic(errEmptyKeys)
	}
	kg := &Keygrip{}
	kg.setKeys(keys)
	return kg
}

// NewRWMutex returns a new keygrip protected by an RWMutex for concurrent use.
func NewRWMutex(keys []string) *Keygrip {
	kg := New(keys)
	kg.mutex = &sync.RWMutex{}
	return kg
}
