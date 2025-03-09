package enmsg

import (
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509"
    "encoding/pem"
    "errors"
    "os"
    "io"
)

const keySize = 2048;

var InvalidKeyFormat = errors.New("Failed to parse PEM key data format");

func NewKey() (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, keySize);
}

func EncodeKey(key *rsa.PrivateKey) []byte { 
    keyData := x509.MarshalPKCS1PrivateKey(key);

    encodedKey := pem.EncodeToMemory(&pem.Block{
        Type: "RSA PRIVATE KEY",
        Bytes: keyData,
    });
    return encodedKey
}

func EncodePublicKey(key *rsa.PublicKey) []byte {
    keyData := x509.MarshalPKCS1PublicKey(key);

    encodedKey := pem.EncodeToMemory(&pem.Block{
        Type: "RSA PUBLIC KEY",
        Bytes: keyData,
    });
    return encodedKey;
}

func DecodeKey(keyData []byte) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode(keyData)
    if block == nil {
        return nil, InvalidKeyFormat;
    }
    return x509.ParsePKCS1PrivateKey(block.Bytes);
}

func DecodePublicKey(keyData []byte) (*rsa.PublicKey, error) {
    block, _ := pem.Decode(keyData);
    if block == nil {
       return nil, InvalidKeyFormat; 
    }
    return x509.ParsePKCS1PublicKey(block.Bytes);
}

func StoreKey(filePath string, key *rsa.PrivateKey) error {
    file, err := os.OpenFile(filePath, os.O_CREATE | os.O_TRUNC | os.O_WRONLY, 0644);
    if err != nil {
        return err;
    }
    defer file.Close();

    _, err = file.Write(EncodeKey(key));
    return err;
}

func LoadKey(filePath string) (*rsa.PrivateKey, error) {
    file, err := os.Open(filePath);
    if err != nil {
        return nil, err;
    }
    defer file.Close();

    keyData, err := io.ReadAll(file);
    if err != nil {
        return nil, err;
    }
    return DecodeKey(keyData);
}

