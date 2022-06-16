package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/tyler-smith/go-bip39"
	"io/ioutil"
)

const DerivationPath = "m/44'/223'/0'"

func DeriveGrandchildECKeyPair(
	masterXPrivKey *hdkeychain.ExtendedKey,
	i uint32,
) (*btcec.PrivateKey, *btcec.PublicKey, error) {
	// First apply the change.
	childXPrivKey, err := masterXPrivKey.Derive(0)
	if err != nil {
		return nil, nil, err
	}
	grandchildXPrivKey, err := childXPrivKey.Derive(i)
	if err != nil {
		return nil, nil, err
	}

	grandchildECPrivKey, err := grandchildXPrivKey.ECPrivKey()
	if err != nil {
		return nil, nil, err
	}
	grandchildECPubKey := grandchildECPrivKey.PubKey()
	return grandchildECPrivKey, grandchildECPubKey, nil
}

func DeriveMasterXPrivKey(seed []byte) (*hdkeychain.ExtendedKey, error) {
	masterXPrivKey, err := hdkeychain.NewMaster(
		seed,
		&chaincfg.MainNetParams,
	)
	if err != nil {
		return nil, err
	}
	path, err := accounts.ParseDerivationPath(DerivationPath)
	if err != nil {
		return nil, err
	}
	for _, i := range path {
		masterXPrivKey, err = masterXPrivKey.Derive(i)
		if err != nil {
			return nil, err
		}
	}
	return masterXPrivKey, nil
}

func GenerateED25519(mn string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	mnemonic := bytes.Join(bytes.Fields([]byte(mn)), []byte(" "))
	b, err := bip39.NewSeedWithErrorChecking(
		string(mnemonic),
		string([]byte{}))
	if err != nil {
		return nil, nil, err
	}
	secret := ed25519.NewKeyFromSeed(b[:32])
	pub := secret.Public().(ed25519.PublicKey)
	return secret, pub, nil
}

func GenerateED22519PrivatePem(mn string, fileName string) error {
	secret, _, err := GenerateED25519(mn)
	if err != nil {
		return err
	}
	b, err := x509.MarshalPKCS8PrivateKey(secret)
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	err = ioutil.WriteFile(fileName, pem.EncodeToMemory(block), 0600)
	if err != nil {
		return err
	}
	return nil
}
