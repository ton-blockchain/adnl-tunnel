package tunnel

import (
	"crypto/ed25519"
	"fmt"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/tl"
	"hash/crc64"
	"sync/atomic"
)

type EncryptionKeys struct {
	CipherKey      []byte
	CipherKeyCRC   uint64
	Seqno          uint32
	SectionPubKey  ed25519.PublicKey
	ReceiverPubKey ed25519.PublicKey
}

func NewEncryptionKeys(sectionPrivate ed25519.PrivateKey, targetPub ed25519.PublicKey) (*EncryptionKeys, error) {
	shKey, err := adnl.SharedKey(sectionPrivate, targetPub)
	if err != nil {
		return nil, fmt.Errorf("shared key calc failed: %v", err)
	}

	return &EncryptionKeys{
		CipherKey:      shKey,
		CipherKeyCRC:   crc64.Checksum(shKey, crcTable),
		SectionPubKey:  sectionPrivate.Public().(ed25519.PublicKey),
		ReceiverPubKey: targetPub,
	}, nil
}

func GenerateEncryptionKeys(targetPub ed25519.PublicKey) (*EncryptionKeys, error) {
	_, sectionPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate key failed: %v", err)
	}
	return NewEncryptionKeys(sectionPrivate, targetPub)
}

func (k *EncryptionKeys) EncryptPayload(payload []byte) ([]byte, error) {
	data, err := encryptStream(k.CipherKeyCRC, k.CipherKey, payload)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %v", err)
	}
	return data, nil
}

func (k *EncryptionKeys) EncryptInstructionsMessage(msg *EncryptedMessage, instructions ...tl.Serializable) error {
	if len(instructions) == 0 {
		return fmt.Errorf("no instructions")
	}

	seqno := atomic.AddUint32(&k.Seqno, 1)
	container := &InstructionsContainer{
		Seqno: seqno,
		List:  instructions,
	}

	instructionsData, err := tl.Serialize(container, true)
	if err != nil {
		return fmt.Errorf("serialize instructions failed: %v", err)
	}

	msg.SectionPubKey = k.SectionPubKey
	msg.Instructions = append(instructionsData, msg.Instructions...)

	if msg.Instructions, err = encryptStream(k.CipherKeyCRC, k.CipherKey, msg.Instructions); err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	return nil
}

func (k *EncryptionKeys) decryptRecvPayload(payload []byte) (tl.Serializable, error) {
	data, err := decryptStream(k.CipherKeyCRC, k.CipherKey, payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload failed: %w", err)
	}

	var pl tl.Serializable
	if _, err = tl.Parse(&pl, data, true); err != nil {
		return nil, fmt.Errorf("parse payload failed: %w", err)
	}

	return pl, nil
}
