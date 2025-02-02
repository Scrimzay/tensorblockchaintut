package wallet

import (
	//"log"
	"math/big"
	"bytes"

	//"github.com/mr-tron/base58"
)

func Base58Encode(input []byte) []byte {
	var result []byte

	x := big.NewInt(0).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58Table[mod.Int64()])
	}

	// Reverse the result
	for i := 0; i < len(result)/2; i++ {
		result[i], result[len(result)-1-i] = result[len(result)-1-i], result[i]
	}

	// Add leading zeros for input bytes that are zero
	for _, b := range input {
		if b == 0 {
			result = append([]byte{base58Table[0]}, result...)
		} else {
			break
		}
	}

	return result
}

func Base58Decode(input []byte) []byte {
	result := big.NewInt(0)
	base := big.NewInt(58)

	for _, b := range input {
		charIndex := bytes.IndexByte(base58Table, b)
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(charIndex)))
	}

	decoded := result.Bytes()

	// Add leading zeros if necessary
	if len(input) > 0 && input[0] == base58Table[0] {
		decoded = append([]byte{0}, decoded...)
	}

	return decoded
}

// chars taken out from base64 to base58: 0 O l I + /