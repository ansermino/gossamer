package crypto

import (
	"errors"
	"fmt"

	wasm "github.com/wasmerio/go-ext-wasm/wasmer"
)

const (
	SR25519_CHAINCODE_SIZE  = 32
	SR25519_KEYPAIR_SIZE    = 96
	SR25519_PUBLIC_SIZE     = 32
	SR25519_SECRET_SIZE     = 64
	SR25519_SEED_SIZE       = 32
	SR25519_SIGNATURE_SIZE  = 64
	SR25519_VRF_OUTPUT_SIZE = 32
	SR25519_VRF_PROOF_SIZE  = 64
)

type SchnorrkelExecutor struct {
	vm   wasm.Instance
}

func NewSchnorrkelExecutor(fp string) (*SchnorrkelExecutor, error) {
	// Reads the WebAssembly module as bytes.
	bytes, err := wasm.ReadBytes(fp)
	if err != nil {
		return nil, fmt.Errorf("cannot read bytes: %s", err)
	}

	// Instantiates the WebAssembly module.
	instance, err := wasm.NewInstance(bytes)
	if err != nil {
		return nil, err
	}

	return &SchnorrkelExecutor{
		vm:   instance,
	}, nil
}

func (se *SchnorrkelExecutor) Stop() {
	se.vm.Close()
}

func (se *SchnorrkelExecutor) Sr25519KeypairFromSeed(seed []byte) ([]byte, error) {
	var out_ptr int32 = 1
	var seed_ptr int32 = out_ptr + SR25519_KEYPAIR_SIZE

	mem := se.vm.Memory.Data()
	copy(mem[seed_ptr:seed_ptr+SR25519_SEED_SIZE], seed)

	_, err := se.Exec("sr25519_keypair_from_seed", out_ptr, seed_ptr)
	if err != nil {
		return nil, err
	}

	keypair_out := make([]byte, SR25519_KEYPAIR_SIZE)
	copy(keypair_out, mem[out_ptr:out_ptr+SR25519_KEYPAIR_SIZE])
	return keypair_out, nil
}

func (se *SchnorrkelExecutor) Sr25519DeriveKeypairHard(keypair, chaincode []byte) ([]byte, error) {
	var out_ptr int32 = 200
	var pair_ptr int32 = out_ptr + SR25519_KEYPAIR_SIZE
	var cc_ptr int32 = pair_ptr + SR25519_KEYPAIR_SIZE

	mem := se.vm.Memory.Data()

	copy(mem[pair_ptr:pair_ptr+SR25519_KEYPAIR_SIZE], keypair)
	copy(mem[cc_ptr:cc_ptr+SR25519_CHAINCODE_SIZE], chaincode)

	_, err := se.Exec("sr25519_derive_keypair_hard", out_ptr, pair_ptr, cc_ptr)
	if err != nil {
		return nil, err
	}

	keypair_out := make([]byte, SR25519_KEYPAIR_SIZE)
	copy(keypair_out, mem[out_ptr:out_ptr+SR25519_KEYPAIR_SIZE])
	return keypair_out, nil
}

func (se *SchnorrkelExecutor) Sr25519DeriveKeypairSoft(keypair, chaincode []byte) ([]byte, error) {
	var out_ptr int32 = 1
	var pair_ptr int32 = out_ptr + SR25519_KEYPAIR_SIZE
	var cc_ptr int32 = pair_ptr + SR25519_KEYPAIR_SIZE

	mem := se.vm.Memory.Data()

	copy(mem[pair_ptr:pair_ptr+SR25519_KEYPAIR_SIZE], keypair)
	copy(mem[cc_ptr:cc_ptr+SR25519_CHAINCODE_SIZE], chaincode)

	_, err := se.Exec("sr25519_derive_keypair_soft", out_ptr, pair_ptr, cc_ptr)
	if err != nil {
		return nil, err
	}

	keypair_out := make([]byte, SR25519_KEYPAIR_SIZE)
	copy(keypair_out, mem[out_ptr:out_ptr+SR25519_KEYPAIR_SIZE])
	return keypair_out, nil
}

func (se *SchnorrkelExecutor) Sr25519DerivePublicSoft(pubkey, chaincode []byte) ([]byte, error) {
	var pubkey_out_ptr int32 = 1
	var public_ptr int32 = pubkey_out_ptr + SR25519_PUBLIC_SIZE
	var cc_ptr int32 = public_ptr + SR25519_PUBLIC_SIZE

	mem := se.vm.Memory.Data()

	copy(mem[public_ptr:public_ptr+SR25519_PUBLIC_SIZE], pubkey)
	copy(mem[cc_ptr:cc_ptr+SR25519_CHAINCODE_SIZE], chaincode)

	_, err := se.Exec("sr25519_derive_public_soft", pubkey_out_ptr, public_ptr, cc_ptr)
	if err != nil {
		return nil, err
	}

	pubkey_out := make([]byte, SR25519_PUBLIC_SIZE)
	copy(pubkey_out, mem[pubkey_out_ptr:pubkey_out_ptr+SR25519_PUBLIC_SIZE])
	return pubkey_out, nil
}

func (se *SchnorrkelExecutor) Sr25519Sign(pubkey, privkey, message []byte) ([]byte, error) {
	public_ptr := 1
	secret_ptr := public_ptr + SR25519_PUBLIC_SIZE
	signature_out_ptr := secret_ptr + SR25519_SECRET_SIZE
	message_ptr := signature_out_ptr + SR25519_SIGNATURE_SIZE

	mem := se.vm.Memory.Data()
	copy(mem[public_ptr:public_ptr+SR25519_PUBLIC_SIZE], pubkey)
	copy(mem[secret_ptr:secret_ptr+SR25519_SECRET_SIZE], privkey)
	copy(mem[message_ptr:message_ptr+len(message)], message)

	_, err := se.Exec("sr25519_sign", signature_out_ptr, public_ptr, secret_ptr, message_ptr, int32(len(message)))
	if err != nil {
		return nil, err
	}

	signature_out := make([]byte, SR25519_SIGNATURE_SIZE)
	copy(signature_out, mem[signature_out_ptr:signature_out_ptr+SR25519_SIGNATURE_SIZE])
	return signature_out, nil
}

func (se *SchnorrkelExecutor) Exec(function string, params... interface{}) (int64, error) {
	wasmFunc, ok := se.vm.Exports[function]
	if !ok {
		return 0, errors.New("could not find exported function")
	}

	res, err := wasmFunc(params...)
	if err != nil {
		return 0, err
	}

	resi := res.ToI64()
	return resi, nil
}