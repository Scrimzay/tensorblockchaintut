package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log"
	"math/big"

	"golang.org/x/crypto/ripemd160"
)

const (
	checksumLength = 4
	version        = byte(0x00)
)

type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

func (w Wallet) Address() []byte {
	pubHash := PublicKeyHash(w.PublicKey)

	versionedHash := append([]byte{version}, pubHash...)
	checksum := Checksum(versionedHash)

	fullHash := append(versionedHash, checksum...)
	address := Base58Encode(fullHash)

	return address
}

func NewKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()

	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}

	pub := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)
	return *private, pub
}

func MakeWallet() *Wallet {
	private, public := NewKeyPair()
	wallet := Wallet{private, public}

	return &wallet
}

func PublicKeyHash(pubKey []byte) []byte {
	pubHash := sha256.Sum256(pubKey)

	hasher := ripemd160.New()
	_, err := hasher.Write(pubHash[:])
	if err != nil {
		log.Panic(err)
	}

	publicRipMD := hasher.Sum(nil)

	return publicRipMD
}

func Checksum(payload []byte) []byte {
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])

	return secondHash[:checksumLength]
}

// SerializePrivateKey encodes the ecdsa.PrivateKey into a byte slice.
func SerializePrivateKey(privateKey ecdsa.PrivateKey) []byte {
	// Encode D, X, and Y fields
	dBytes := privateKey.D.Bytes()
	xBytes := privateKey.PublicKey.X.Bytes()
	yBytes := privateKey.PublicKey.Y.Bytes()

	// Combine into a single byte slice
	return append(append(dBytes, xBytes...), yBytes...)
}

// DeserializePrivateKey decodes a byte slice into an ecdsa.PrivateKey.
func DeserializePrivateKey(data []byte) ecdsa.PrivateKey {
	curve := elliptic.P256()

	// Extract D, X, and Y from the byte slice
	d := new(big.Int).SetBytes(data[:32])
	x := new(big.Int).SetBytes(data[32:64])
	y := new(big.Int).SetBytes(data[64:96])

	privateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}

	return privateKey
}

var base58Table = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func ValidateAddress(address string) bool {
	// Decode the Base58 address
	pubKeyHash := Base58Decode([]byte(address))

	// Ensure the decoded address is long enough to contain version and checksum
	if len(pubKeyHash) < checksumLength+1 {
		return false
	}

	// Extract the checksum and version
	actualChecksum := pubKeyHash[len(pubKeyHash)-checksumLength:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-checksumLength]

	// Calculate the target checksum
	targetChecksum := Checksum(append([]byte{version}, pubKeyHash...))

	// Compare the checksums
	return bytes.Equal(actualChecksum, targetChecksum)
}