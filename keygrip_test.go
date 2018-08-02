package keygrip

import (
	"strings"
	"testing"
)

func TestKeygrip(t *testing.T) {
	t.Run("verify", func(t *testing.T) {
		kg := New([]string{
			"a",
		})
		data := "tree.xie"
		hash := kg.Sign(data)
		if !kg.Verify(data, hash) {
			t.Fatalf("verify fail")
		}
	})

	t.Run("index", func(t *testing.T) {
		kg := New([]string{
			"a",
		})
		data := "tree.xie"
		hash := kg.Sign(data)
		kg.AddKey("b")
		if kg.Index(data, hash) != 1 {
			t.Fatalf("get index fail")
		}
	})

	t.Run("keys", func(t *testing.T) {
		kg := New([]string{
			"a",
			"b",
		})
		keys := kg.Keys()
		if len(keys) != 2 || strings.Join(keys, ",") != "a,b" {
			t.Fatalf("get keys fail")
		}
	})

	t.Run("add/remove key", func(t *testing.T) {
		a := "a"
		b := "b"
		kg := New([]string{
			a,
		})
		data := "tree.xie"
		hash := kg.Sign(data)
		kg.AddKey(b)
		if len(kg.Keys()) != 2 || kg.Keys()[0] != b {
			t.Fatalf("add key fail")
		}
		if !kg.Verify(data, hash) {
			t.Fatalf("verify fail after add new key")
		}
		kg.RemoveKey(a)
		if len(kg.Keys()) != 1 || kg.Keys()[0] != b {
			t.Fatalf("remove key fail")
		}
		if kg.Verify(data, hash) {
			t.Fatalf("verify should be fail after remove key")
		}
	})

	t.Run("remove all keys", func(t *testing.T) {
		kg := New([]string{
			"a",
			"b",
		})
		kg.RemoveAllKeys()
		if len(kg.Keys()) != 0 {
			t.Fatalf("remove all keys fail")
		}
	})
}

func BenchmarkSign(b *testing.B) {
	kg := New([]string{
		"tree.xie",
		"vicanso",
	})
	for i := 0; i < b.N; i++ {
		kg.Sign("1533082453554-SEyVMmjzVtqtEiVlDoqrneXauXKhPD3w")
	}
}

func BenchmarkVerify(b *testing.B) {
	kg := New([]string{
		"tree.xie",
		"vicanso",
	})
	data := "1533082453554-SEyVMmjzVtqtEiVlDoqrneXauXKhPD3w"
	hash := kg.Sign(data)
	for i := 0; i < b.N; i++ {
		kg.Verify(data, hash)
	}
}
