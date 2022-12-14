package main

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"log"
	"reflect"
)

type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

type Account struct {
	accountID string
	wallet    KeyPair
	balance   int
}

type Operation struct {
	sender    Account
	receiver  Account
	amount    int
	signature []byte
}

type Transaction struct {
	TransactionID    string
	ArrayOfOperation []Operation
	nonce            int
}

func Hash(objs ...interface{}) []byte {
	digester := md5.New()
	for _, ob := range objs {
		fmt.Fprint(digester, reflect.TypeOf(ob))
		fmt.Fprint(digester, ob)
	}
	return digester.Sum(nil)
}
func GenerateNonce() int {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return 0
	}

	return int(binary.BigEndian.Uint16(nonceBytes))
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

func genAccount() Account {
	//wallet
	keys := genKeyPair()

	// accountID
	dst := make([]byte, hex.EncodedLen(len(keys.PublicKey)))
	hex.Encode(dst, keys.PublicKey)
	accountID := fmt.Sprintf("%s\n", dst)

	return Account{
		accountID: accountID,
		wallet:    keys,
		balance:   0,
	}

}

func (acc *Account) addKeyPairToWallet(pair KeyPair) {
	acc.wallet = pair
}

func (acc *Account) updateBalance(balance int) {
	acc.balance = balance
}

func (acc *Account) getBalance() int {
	return acc.balance
}

func (acc *Account) printBalance() {
	fmt.Println(acc.balance)
}

func (acc *Account) signDataAcc(message string) []byte {
	privateK := acc.wallet.PrivateKey
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

func (acc *Account) createOperation(recipient Account, amount int) Operation {
	return Operation{
		sender:    *acc,
		receiver:  recipient,
		amount:    amount,
		signature: Operation{}.signature,
	}
}

func createOperation(sender Account, receiver Account, amount int, signature []byte) Operation {
	return Operation{
		sender:    sender,
		receiver:  receiver,
		amount:    amount,
		signature: signature,
	}
}

func verifyOperation(operation Operation) bool {
	if operation.amount > operation.sender.balance {
		return false
	}
	if hexutil.Encode(operation.signature) != hexutil.Encode(operation.sender.signDataAcc("transfer(address,uint256)")) {
		return false
	}
	return true
}

func createTransaction(setOfOperation []Operation, nonce int) Transaction {
	transactionId := fmt.Sprintf("%x", Hash(setOfOperation, nonce))
	nonce_for_tx := GenerateNonce()
	return Transaction{
		TransactionID:    transactionId,
		ArrayOfOperation: setOfOperation,
		nonce:            nonce_for_tx,
	}
}
