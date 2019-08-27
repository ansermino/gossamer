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

	pair, err := common.HexToBytes("0x28b0ae221c6bb06856b287f60d7ea0d98552ea5a16db16956849aa371db3eb51fd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca3446ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
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

	expected, err := common.HexToBytes("0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
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

	pair, err := common.HexToBytes("0x28b0ae221c6bb06856b287f60d7ea0d98552ea5a16db16956849aa371db3eb51fd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca3446ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
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

	expected, err := common.HexToBytes("0x40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a")
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

	//signature_out := make([]byte, 64)
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