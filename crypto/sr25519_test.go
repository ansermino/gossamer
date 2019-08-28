package crypto

import (
	"bytes"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/ChainSafe/gossamer/common"
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

func newRandomKeypair(t *testing.T) []byte {
	se, err := newSchnorrkel(t)
	if err != nil {
		t.Fatal(err)
	}

	seed := make([]byte, SR25519_SEED_SIZE)
	rand.Read(seed)

	keypair, err := se.Sr25519KeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}

	return keypair
}

func TestSr25519KeypairFromSeed(t *testing.T) {
	keypair_out := newRandomKeypair(t)
	empty := make([]byte, SR25519_KEYPAIR_SIZE)

	if bytes.Equal(keypair_out, empty) {
		t.Fatalf("fail to generate keypair from seed: got empty expected non-empty")
	}
}

func TestDeriveKeypairHard(t *testing.T) {
	se, err := newSchnorrkel(t)
	if err != nil {
		t.Fatal(err)
	}

	pair, err := common.HexToBytes("0x4c1250e05afcd79e74f6c035aee10248841090e009b6fd7ba6a98d5dc743250cafa4b32c608e3ee2ba624850b3f14c75841af84b16798bf1ee4a3875aa37a2cee661e416406384fe1ca091980958576d2bff7c461636e9f22c895f444905ea1f")
	if err != nil {
		t.Fatal(err)
	}

	cc, err := common.HexToBytes("0x14416c6963650000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	keypair_out, err := se.Sr25519DeriveKeypairHard(pair, cc)
	if err != nil {
		t.Fatal(err)
	}

	expected, err := common.HexToBytes("0xd8db757f04521a940f0237c8a1e44dfbe0b3e39af929eb2e9e257ba61b9a0a1a")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expected, keypair_out[64:]) {
		t.Errorf("actual pubkey does not match expected: got %x expected %x", keypair_out[64:], expected)
	}
}

func TestDeriveKeypairSoft(t *testing.T) {
	se, err := newSchnorrkel(t)
	if err != nil {
		t.Fatal(err)
	}

	pair, err := common.HexToBytes("0x4c1250e05afcd79e74f6c035aee10248841090e009b6fd7ba6a98d5dc743250cafa4b32c608e3ee2ba624850b3f14c75841af84b16798bf1ee4a3875aa37a2cee661e416406384fe1ca091980958576d2bff7c461636e9f22c895f444905ea1f")
	if err != nil {
		t.Fatal(err)
	}

	cc, err := common.HexToBytes("0x0c666f6f00000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	keypair_out, err := se.Sr25519DeriveKeypairSoft(pair, cc)
	if err != nil {
		t.Fatal(err)
	}

	expected, err := common.HexToBytes("0xb21e5aabeeb35d6a1bf76226a6c65cd897016df09ef208243e59eed2401f5357")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expected, keypair_out[64:]) {
		t.Errorf("actual pubkey does not match expected: got %x expected %x", keypair_out[64:], expected)
	}
}

func TestDerivePublicSoft(t *testing.T) {
	se, err := newSchnorrkel(t)
	if err != nil {
		t.Fatal(err)
	}

	keypair_out := newRandomKeypair(t)
	public := keypair_out[64:]

	cc, err := common.HexToBytes("0x0c666f6f00000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	pubkey_out, err := se.Sr25519DerivePublicSoft(public, cc)
	if err != nil {
		t.Fatal(err)
	}

	empty := make([]byte, SR25519_KEYPAIR_SIZE)
	if bytes.Equal(pubkey_out, empty) {
		t.Errorf("actual pubkey does not match expected: got empty expected non-empty")
	}
}

func TestSignAndVerify(t *testing.T) {
	se, err := newSchnorrkel(t)
	if err != nil {
		t.Fatal(err)
	}

	keypair := newRandomKeypair(t)

	public := keypair[64:]
	secret := keypair[:64]

	message := []byte("this is a message")

	sig, err := se.Sr25519Sign(public, secret, message)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(sig)

	// ver, err := Sr25519_verify(signature_out, message_ptr, public_ptr, message_length)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// if ver != true {
	// 	t.Error("did not verify signature")
	// }
}

func TestVrfSignAndVerify(t *testing.T) {
	se, err := newSchnorrkel(t)
	if err != nil {
		t.Fatal(err)
	}

	keypair := newRandomKeypair(t)
	message := []byte("this is a message")	

	limit := make([]byte, SR25519_VRF_OUTPUT_SIZE)
	for i, _ := range limit {
		limit[i] = 0xff
	}

	out_and_proof, is_less, err := se.Sr25519VrfSign(keypair, message, limit)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(out_and_proof)
	t.Log(is_less)
}
