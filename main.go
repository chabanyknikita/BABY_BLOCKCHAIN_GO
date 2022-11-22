package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
)

type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

func genKeyPair() KeyPair {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	return KeyPair{
		PrivateKey: privateKeyBytes,
		PublicKey:  publicKeyBytes,
	}
}

func printKeyPair() {
	privateKey := genKeyPair().PrivateKey
	publicKey := genKeyPair().PublicKey
	fmt.Println("PRIVATE KEY: ", hexutil.Encode(privateKey)[2:])
	fmt.Println("PUBLIC KEY:  ", hexutil.Encode(publicKey)[4:])

}

func signData(privateK []byte, message string) []byte {
	privateKey, err := crypto.HexToECDSA(hexutil.Encode(privateK)[2:])
	if err != nil {
		log.Fatal(err)
	}

	data := []byte(message)
	hash := crypto.Keccak256Hash(data)

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	return signature
}

func verifySignature(privateK, signature []byte, message string) bool {
	privateKey, err := crypto.HexToECDSA(hexutil.Encode(privateK)[2:])
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}
	data := []byte(message)
	hash := crypto.Keccak256Hash(data)
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	signatureNoRecoverID := signature[:len(signature)-1]
	verified := crypto.VerifySignature(publicKeyBytes, hash.Bytes(), signatureNoRecoverID)
	return verified
}

func printSignature() {
	signature := signData(genKeyPair().PrivateKey, "")
	fmt.Println("SIGNATURE:   ", hexutil.Encode(signature))
}
