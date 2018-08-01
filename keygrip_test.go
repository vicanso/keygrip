package keygrip

import (
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

	t.Run("add/remove key", func(t *testing.T) {
		a := "a"
		b := "b"
		kg := New([]string{
			a,
		})
		data := "tree.xie"
		hash := kg.Sign(data)
		kg.AddKey(b)
		if len(kg.Keys) != 2 || string(kg.Keys[0]) != b {
			t.Fatalf("add key fail")
		}
		if !kg.Verify(data, hash) {
			t.Fatalf("verify fail after add new key")
		}
		kg.RemoveKey(a)
		if len(kg.Keys) != 1 || string(kg.Keys[0]) != b {
			t.Fatalf("remove key fail")
		}
		if kg.Verify(data, hash) {
			t.Fatalf("verify should be fail after remove key")
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
