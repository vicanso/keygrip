package keygrip

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

	t.Run("remove all keys", func(t *testing.T) {
		kg := New([]string{
			"a",
			"b",
		})
		kg.RemoveAllKeys()
		assert.Equal(0, len(kg.Keys()))
	})
}

func TestKeygripRWMutex(t *testing.T) {
	assert := assert.New(t)

	kg := NewRWMutex([]string{
		"a",
		"b",
	})
	data := []byte("tree.xie")
	hash := kg.Sign(data)
	assert.True(kg.Verify(data, hash))
	assert.Equal(0, kg.Index(data, hash))

	go func() {
		for i := 0; i < 100; i++ {
			_ = kg.Verify([]byte("data"), []byte("digest"))
		}
	}()
	go func() {
		for i := 0; i < 100; i++ {
			kg.AddKey(strconv.Itoa(i))
		}
	}()
	go func() {
		for i := 0; i < 100; i++ {
			kg.RemoveKey(strconv.Itoa(i))
		}
	}()
	go func() {
		for i := 0; i < 100; i++ {
			kg.SetKeys([]string{
				"a",
			})
		}
	}()

	time.Sleep(100 * time.Millisecond)
	assert.NotEmpty(kg.Keys())
}

func BenchmarkSha1(b *testing.B) {
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
	for i := 0; i < b.N; i++ {
		kg.Verify(data, hash)
	}
}
