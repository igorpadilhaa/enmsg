package enmsg 

import (
    "crypto/rsa"
    "crypto/aes"
    "crypto/sha256"
    "crypto/rand"
    "crypto/cipher"

    "log"
    "fmt"
);

const aesKeySize = 32;
var rsaLabel = []byte("MESSAGE-CIPHER-LABEL");

type MessageCipher struct {
    publicKey *rsa.PublicKey
    privateKey *rsa.PrivateKey
}

func NewCipher(publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) MessageCipher {
    return MessageCipher{publicKey, privateKey};
}

func newAESKey() []byte {
    key := make([]byte, aesKeySize);
    _, err := rand.Reader.Read(key);
    if err != nil {
        log.Fatalf("Failed to generate aes key: %s\n", err);
    }
    return key;
}

func encryptAESKey(aesKey []byte, rsaKey *rsa.PublicKey) ([]byte, error) {
    return rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, aesKey, rsaLabel);
}

func aeadCipher(key []byte) (cipher.AEAD, error) {
    aesCipher, err := aes.NewCipher(key);
    if err != nil {
        return nil, err;
    }
    return cipher.NewGCMWithRandomNonce(aesCipher);
}

func (cipher *MessageCipher) Encrypt(data []byte) (Message, error) {
    aesKey := newAESKey();
    aesCipher, err := aeadCipher(aesKey);

    if err != nil {
        return Message{}, fmt.Errorf("Failed to instantiate AES cipher: %w", err);
    }

    encryptedKey, err := encryptAESKey(aesKey, cipher.publicKey);
    if err != nil {
        return Message{}, err;
    }

    encryptedData := aesCipher.Seal(nil, nil, data, nil);
    if err != nil {
        return Message{}, err;
    }
    return Message{encryptedKey, encryptedData}, nil;
}

func (cipher *MessageCipher) Decrypt(message Message) (Message, error) {
    decryptedKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, cipher.privateKey, message.AesKey, rsaLabel);
    if err != nil {
        return Message{}, err;
    }

    aesCipher, err := aeadCipher(decryptedKey);
    if err != nil {
        return Message{}, fmt.Errorf("failed to instantiate AES cipher: %w", err);
    }

    decryptedData, err := aesCipher.Open(nil, nil, message.Data, nil);
    return Message{decryptedKey, decryptedData}, nil;
}
