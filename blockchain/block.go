package blockchain

import (
	"bytes"
	"time"
	"fmt"
	"encoding/gob"
	"log"
)

type Block struct {
	Timestamp int64
	Hash     []byte
	Transactions []*Transaction
	PrevHash []byte
	Nonce    int
	Height int
}

func (b *Block) HashTransactions() []byte {
	var txHashes [][]byte

	for _, tx := range b.Transactions {
		txHashes = append(txHashes, tx.Serialize())
	}
	tree := NewMerkleTree(txHashes)

	return tree.RootNode.Data
}

func CreateBlock(txs []*Transaction, prevHash []byte, height int) *Block {
	block := &Block{time.Now().Unix(), []byte{}, txs, prevHash, 0, height}
	pow := NewProof(block)
	nonce, hash := pow.Run()

	block.Hash = hash[:]
	block.Nonce = nonce

	return block
}

func Genesis(coinbase *Transaction) *Block {
	return CreateBlock([]*Transaction{coinbase}, []byte{}, 0)
}

func (b *Block) Serialize() []byte {
	var res bytes.Buffer
	encoder := gob.NewEncoder(&res)

	err := encoder.Encode(b)
	HandleErrPanic(err)

	// Debug: Print serialized block
	fmt.Printf("Serialized block: %x\n", res.Bytes())

	return res.Bytes()
}

func Deserialize(data []byte) *Block {
	var block Block

	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&block)
	HandleErrPanic(err)

	// Debug: Print deserialized block
	fmt.Printf("Deserialized block: %+v\n", block)

	return &block
}

func HandleErrPanic(err error) {
	if err != nil {
		log.Panic(err)
	}
}