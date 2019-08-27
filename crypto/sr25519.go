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

func (se *SchnorrkelExecutor) Exec(function string, data, len int32) (int64, error) {
	wasmFunc, ok := se.vm.Exports[function]
	if !ok {
		return 0, errors.New("could not find exported function")
	}

	res, err := wasmFunc(data, len)
	if err != nil {
		return 0, err
	}

	resi := res.ToI64()
	return resi, nil
}