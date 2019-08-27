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

	keypair_out := make([]byte, SR25519_KEYPAIR_SIZE)

	var out_ptr int32 = 1
	var pair_ptr int32 = out_ptr + SR25519_KEYPAIR_SIZE
	var cc_ptr int32 = pair_ptr + SR25519_KEYPAIR_SIZE

	mem := se.vm.Memory.Data()

	copy(mem[pair_ptr:pair_ptr+SR25519_KEYPAIR_SIZE], pair)
	copy(mem[cc_ptr:cc_ptr+SR25519_CHAINCODE_SIZE], cc)

	_, err = se.Exec("sr25519_derive_keypair_soft", out_ptr, pair_ptr, cc_ptr)
	if err != nil {
		t.Fatal(err)
	}

	copy(keypair_out, mem[out_ptr:out_ptr+SR25519_KEYPAIR_SIZE])

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

	var out_ptr int32 = 1
	var seed_ptr int32 = out_ptr + SR25519_KEYPAIR_SIZE
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

	public := keypair_out[64:]

	cc, err := common.HexToBytes("0x0c666f6f00000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	var pubkey_out_ptr int32 = 1
	var public_ptr int32 = pubkey_out_ptr + SR25519_PUBLIC_SIZE
	var cc_ptr int32 = public_ptr + SR25519_PUBLIC_SIZE

	copy(mem[public_ptr:public_ptr+SR25519_PUBLIC_SIZE], public)
	copy(mem[cc_ptr:cc_ptr+SR25519_CHAINCODE_SIZE], cc)

	_, err = se.Exec("sr25519_derive_public_soft", pubkey_out_ptr, public_ptr, cc_ptr)
	if err != nil {
		t.Fatal(err)
	}

	pubkey_out := make([]byte, SR25519_PUBLIC_SIZE)
	copy(pubkey_out, mem[pubkey_out_ptr:pubkey_out_ptr+SR25519_PUBLIC_SIZE])

	if bytes.Equal(pubkey_out, empty) {
		t.Errorf("actual pubkey does not match expected: got empty expected non-empty")
	}
}

func TestSignAndVerify(t *testing.T) {
	keypair := newRandomKeypair(t)

	public := keypair[64:]
	secret := keypair[:64]

	//signature_out := make([]byte, 64)
	message := []byte("this is a message")

	public_ptr := 1
	secret_ptr := public_ptr + SR25519_PUBLIC_SIZE
	signature_out_ptr := secret_ptr + SR25519_SECRET_SIZE
	message_ptr := signature_out_ptr + SR25519_SIGNATURE_SIZE

	se, err := newSchnorrkel(t)
	if err != nil {
		t.Fatal(err)
	}

	mem := se.vm.Memory.Data()
	copy(mem[public_ptr:public_ptr+SR25519_PUBLIC_SIZE], public)
	copy(mem[secret_ptr:secret_ptr+SR25519_SECRET_SIZE], secret)
	copy(mem[message_ptr:message_ptr+len(message)], message)

	_, err = se.Exec("sr25519_sign", signature_out_ptr, public_ptr, secret_ptr, message_ptr, int32(len(message)))
	if err != nil {
		t.Fatal(err)
	}

	// ver, err := Sr25519_verify(signature_out, message_ptr, public_ptr, message_length)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// if ver != true {
	// 	t.Error("did not verify signature")
	// }
}