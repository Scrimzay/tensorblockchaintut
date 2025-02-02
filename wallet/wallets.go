package wallet

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// not using badger for this because badger will be used solely for blockchain
// and wallet should be seperate from blockchain module

const walletFile = "./tmp/wallets_%s.data"

type Wallets struct {
	Wallets map[string]*Wallet
}

func CreateWallets(nodeId string) (*Wallets, error) {
	wallets := Wallets{}
	wallets.Wallets = make(map[string]*Wallet)

	err := wallets.LoadFile(nodeId)

	return &wallets, err
}

func (ws *Wallets) AddWallet() string {
	wallet := MakeWallet()
	address := fmt.Sprintf("%s", wallet.Address())

	ws.Wallets[address] = wallet

	return address
}

func (ws *Wallets) GetAllAddresses() []string {
	var addresses []string

	for address := range ws.Wallets {
		addresses = append(addresses, address)
	}

	return addresses
}

func (ws Wallets) GetWallet(address string) Wallet {
	return *ws.Wallets[address]
}

func (ws *Wallets) LoadFile(nodeId string) error {
	walletFile := fmt.Sprintf(walletFile, nodeId)
	if _, err := os.Stat(walletFile); os.IsNotExist(err) {
		return err
	}

	fileContent, err := ioutil.ReadFile(walletFile)
	if err != nil {
		return err
	}

	// Deserialize the wallets from the file
	ws.Wallets = make(map[string]*Wallet)
	for len(fileContent) > 0 {
		// Read address length
		addressLen := int(fileContent[0])
		fileContent = fileContent[1:]

		// Read address
		address := string(fileContent[:addressLen])
		fileContent = fileContent[addressLen:]

		// Read private key length
		privateKeyLen := int(fileContent[0])
		fileContent = fileContent[1:]

		// Read private key
		privateKeyBytes := fileContent[:privateKeyLen]
		fileContent = fileContent[privateKeyLen:]

		// Read public key length
		publicKeyLen := int(fileContent[0])
		fileContent = fileContent[1:]

		// Read public key
		publicKeyBytes := fileContent[:publicKeyLen]
		fileContent = fileContent[publicKeyLen:]

		// Deserialize private key
		privateKey := DeserializePrivateKey(privateKeyBytes)

		// Create wallet
		wallet := Wallet{
			PrivateKey: privateKey,
			PublicKey:  publicKeyBytes,
		}

		ws.Wallets[address] = &wallet
	}

	return nil
}

func (ws *Wallets) SaveFile(nodeId string) {
	var content []byte
	walletFile := fmt.Sprintf(walletFile, nodeId)

	// Serialize each wallet
	for address, wallet := range ws.Wallets {
		// Serialize address
		addressBytes := []byte(address)
		content = append(content, byte(len(addressBytes)))
		content = append(content, addressBytes...)

		// Serialize private key
		privateKeyBytes := SerializePrivateKey(wallet.PrivateKey)
		content = append(content, byte(len(privateKeyBytes)))
		content = append(content, privateKeyBytes...)

		// Serialize public key
		publicKeyBytes := wallet.PublicKey
		content = append(content, byte(len(publicKeyBytes)))
		content = append(content, publicKeyBytes...)
	}

	// Write to file
	err := ioutil.WriteFile(walletFile, content, 0644)
	if err != nil {
		log.Panic(err)
	}
}