package crypto

import (
	"bytes"
	"crypto/rand"
	"path/filepath"
	"testing"
)

const SCHNORRKEL_FP = "sr25519crust.wasm"

func newSchnorrkel(t *testing.T) (*SchnorrkelExecutor, error) {
	fp, err := filepath.Abs(SCHNORRKEL_FP)
	if err != nil {
		t.Fatal("could not create filepath")
	}

	se, err := NewSchnorrkelExecutor(fp)
	if err != nil {
		t.Fatal(err)
	} else if se == nil {
		t.Fatal("did not create new SchnorrkelExecutor")
	}

	return se, err
}


func TestSr25519_keypair_from_seed(t *testing.T) {
	se, err := newSchnorrkel(t)
	if err != nil {
		t.Fatal(err)
	}

	var out_ptr int32 = 1
	var seed_ptr  int32 = 100
	seed := []byte{}

	buf := make([]byte, SR25519_SEED_SIZE)
	rand.Read(buf)
	seed = buf

	mem := se.vm.Memory.Data()

	copy(mem[seed_ptr:seed_ptr+SR25519_SEED_SIZE], seed)

	_, err = se.Exec("sr25519_keypair_from_seed", out_ptr, seed_ptr)
	if err != nil {
		t.Fatal(err)
	}

	keypair_out := make([]byte, SR25519_KEYPAIR_SIZE)
	copy(keypair_out, mem[out_ptr:out_ptr+SR25519_KEYPAIR_SIZE])
	empty := make([]byte, SR25519_KEYPAIR_SIZE)

	if bytes.Equal(keypair_out, empty) {
		t.Fatalf("fail to generate keypair from seed: got empty expected non-empty")
	}
}