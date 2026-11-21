package config

import "testing"

func TestListenAddr(t *testing.T) {
	t.Setenv("ADDR", "")
	if got := ListenAddr(); got != ":8080" {
		t.Fatalf("default ListenAddr = %q", got)
	}
	t.Setenv("ADDR", ":9999")
	if got := ListenAddr(); got != ":9999" {
		t.Fatalf("ListenAddr = %q", got)
	}
}
