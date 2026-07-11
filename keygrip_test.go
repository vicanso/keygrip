package keygrip

import (
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeygrip(t *testing.T) {
	assert := assert.New(t)
	t.Run("verify", func(t *testing.T) {
		kg := New([]string{
			"a",
		})
		data := []byte("tree.xie")
		hash := kg.Sign(data)
		assert.True(kg.Verify(data, hash))
	})

	t.Run("index", func(t *testing.T) {
		kg := New([]string{
			"a",
		})
		data := []byte("tree.xie")
		hash := kg.Sign(data)
		kg.AddKey("b")
		assert.Equal(1, kg.Index(data, hash))
	})

	t.Run("keys", func(t *testing.T) {
		kg := New([]string{
			"a",
			"b",
		})
		keys := kg.Keys()
		assert.Equal(2, len(keys))
		assert.Equal("a,b", strings.Join(keys, ","))
	})

	t.Run("add/remove key", func(t *testing.T) {
		a := "a"
		b := "b"
		kg := New([]string{
			a,
		})
		data := []byte("tree.xie")
		hash := kg.Sign(data)
		kg.AddKey(b)
		assert.Equal(2, len(kg.keys))
		assert.Equal(b, kg.Keys()[0])
		assert.True(kg.Verify(data, hash))
		kg.RemoveKey(a)

		assert.Equal(1, len(kg.keys))
		assert.Equal(b, kg.Keys()[0])

		assert.False(kg.Verify(data, hash))
	})

	t.Run("add duplicate key is no-op", func(t *testing.T) {
		kg := New([]string{"a", "b"})
		kg.AddKey("a")
		assert.Equal([]string{"a", "b"}, kg.Keys())
	})

	t.Run("remove missing key is no-op", func(t *testing.T) {
		kg := New([]string{"a", "b"})
		kg.RemoveKey("missing")
		assert.Equal([]string{"a", "b"}, kg.Keys())
	})

	t.Run("remove last key is no-op", func(t *testing.T) {
		kg := New([]string{"only"})
		data := []byte("payload")
		sig := kg.Sign(data)
		kg.RemoveKey("only")
		assert.Equal([]string{"only"}, kg.Keys())
		assert.True(kg.Verify(data, sig))
		// Still signs with the protected last key.
		assert.Equal(sig, kg.Sign(data))
	})

	t.Run("set keys", func(t *testing.T) {
		kg := New([]string{"a"})
		kg.SetKeys([]string{"x", "y"})
		assert.Equal([]string{"x", "y"}, kg.Keys())
		data := []byte("payload")
		hash := kg.Sign(data)
		assert.Equal(0, kg.Index(data, hash))
		assert.True(kg.Verify(data, hash))
	})

	t.Run("set keys empty panics", func(t *testing.T) {
		kg := New([]string{"a"})
		assert.Panics(func() {
			kg.SetKeys(nil)
		})
		assert.Panics(func() {
			kg.SetKeys([]string{})
		})
		// Previous keys remain usable after failed SetKeys.
		assert.Equal([]string{"a"}, kg.Keys())
	})

	t.Run("verify with rotated keys", func(t *testing.T) {
		kg := New([]string{"old"})
		data := []byte("cookie-value")
		oldSig := kg.Sign(data)
		kg.AddKey("new")
		// Old signature still verifies (index 1), new signatures use front key.
		assert.True(kg.Verify(data, oldSig))
		assert.Equal(1, kg.Index(data, oldSig))
		newSig := kg.Sign(data)
		assert.Equal(0, kg.Index(data, newSig))
		assert.NotEqual(string(oldSig), string(newSig))
	})

	t.Run("index invalid digest", func(t *testing.T) {
		kg := New([]string{"a"})
		data := []byte("tree.xie")
		// Empty string decodes successfully to 0 bytes → no match (-1).
		assert.Equal(-1, kg.Index(data, []byte("")))
		// Invalid base64 alphabet → -2.
		assert.Equal(-2, kg.Index(data, []byte("!!!not-base64!!!")))
		// Valid encoding, wrong signature → -1.
		assert.Equal(-1, kg.Index(data, []byte("VOauNTAF3i24kD9EN5foGvhXNnI")))
		assert.False(kg.Verify(data, []byte("!!!not-base64!!!")))
		assert.False(kg.Verify(data, []byte("")))
	})

	t.Run("new empty panics", func(t *testing.T) {
		assert.Panics(func() {
			New(nil)
		})
		assert.Panics(func() {
			New([]string{})
		})
	})

	t.Run("readme vector", func(t *testing.T) {
		kg := New([]string{"key1", "key2"})
		data := []byte("tree.xie")
		want := []byte("lOvR3UDUZm9jkNUsvtOyCnnxVkCn3QOaElodqz54_A8")
		assert.Equal(want, kg.Sign(data))
		assert.True(kg.Verify(data, want))
		assert.Equal(0, kg.Index(data, want))
	})
}

func TestKeygripRWMutex(t *testing.T) {
	kg := NewRWMutex([]string{
		"a",
		"b",
	})
	data := []byte("tree.xie")
	hash := kg.Sign(data)
	require.True(t, kg.Verify(data, hash))
	require.Equal(t, 0, kg.Index(data, hash))

	var wg sync.WaitGroup
	const n = 200

	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			_ = kg.Verify(data, hash)
			_ = kg.Sign(data)
			_ = kg.Index(data, hash)
			_ = kg.Keys()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			kg.AddKey(strconv.Itoa(i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			kg.RemoveKey(strconv.Itoa(i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			kg.SetKeys([]string{"a", "b"})
		}
	}()

	wg.Wait()
	assert.NotEmpty(t, kg.Keys())
	// Must still be able to sign after concurrent mutation.
	assert.NotEmpty(t, kg.Sign(data))
}

func TestHMACPoolReuse(t *testing.T) {
	// Many sequential signs should keep producing the same digest (pool Reset works).
	kg := New([]string{"pool-key", "other"})
	data := []byte("reuse-me")
	first := kg.Sign(data)
	for i := 0; i < 100; i++ {
		assert.Equal(t, first, kg.Sign(data))
		assert.True(t, kg.Verify(data, first))
	}
	// After rotation, pool for new front key is used.
	kg.AddKey("front")
	rotated := kg.Sign(data)
	assert.NotEqual(t, first, rotated)
	assert.True(t, kg.Verify(data, first))
	assert.True(t, kg.Verify(data, rotated))
}

func BenchmarkSha256(b *testing.B) {
	b.ReportAllocs()
	data := []byte("1533082453554-SEyVMmjzVtqtEiVlDoqrneXauXKhPD3w")
	key := []byte("tree.xie")
	for i := 0; i < b.N; i++ {
		sign(data, key)
	}
}

func BenchmarkSign(b *testing.B) {
	b.ReportAllocs()
	kg := New([]string{
		"tree.xie",
		"vicanso",
	})
	data := []byte("1533082453554-SEyVMmjzVtqtEiVlDoqrneXauXKhPD3w")
	// Warm the pool.
	_ = kg.Sign(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kg.Sign(data)
	}
}

func BenchmarkVerify(b *testing.B) {
	b.ReportAllocs()
	kg := New([]string{
		"tree.xie",
		"vicanso",
	})
	data := []byte("1533082453554-SEyVMmjzVtqtEiVlDoqrneXauXKhPD3w")
	hash := kg.Sign(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kg.Verify(data, hash)
	}
}

func BenchmarkVerifyMiss(b *testing.B) {
	b.ReportAllocs()
	kg := New([]string{
		"tree.xie",
		"vicanso",
		"extra-key-1",
		"extra-key-2",
	})
	data := []byte("1533082453554-SEyVMmjzVtqtEiVlDoqrneXauXKhPD3w")
	// Valid encoding length but wrong signature — forces full key scan.
	bad := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	// Warm pools.
	_ = kg.Verify(data, bad)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kg.Verify(data, bad)
	}
}

func BenchmarkSignParallel(b *testing.B) {
	b.ReportAllocs()
	kg := NewRWMutex([]string{
		"tree.xie",
		"vicanso",
	})
	data := []byte("1533082453554-SEyVMmjzVtqtEiVlDoqrneXauXKhPD3w")
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			kg.Sign(data)
		}
	})
}
