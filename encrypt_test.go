package enmsg 

import (
    "testing"
    "crypto/rand"   
    "slices"
)

func randomData(size int, t *testing.T) []byte {
    data := make([]byte, size);
    _, err := rand.Reader.Read(data[:]);
    if err != nil {
        t.Fatalf("failed to generated data to test: %s", err);
    }
    return data;
}

func TestEncryption(t *testing.T) {
    t.Parallel();

    data := randomData(1024 * 1024 * 50, t);
    key, err := NewKey();

    if err != nil {
        t.Fatalf("failed to generate test key: %s", err);
    }

    cipher := NewCipher(&key.PublicKey, key);

    message, err := cipher.Encrypt(data);
    if err != nil {
        t.Fatalf("failed to encrypt data: %s", err);
    }

    decrypted, err := cipher.Decrypt(message);
    if err != nil {
        t.Fatalf("failed to decrypt data: %s", err);
    }

    if !slices.Equal(decrypted.Data, data) {
        t.Fatal("the decryped data differs from the source");
    }
}

func TestMessageByteConversion(t *testing.T) {
    t.Parallel();

    message := Message{
        randomData(32, t),
        randomData(30 * 1024, t),
    };

    bytes, err := message.Bytes();
    if err != nil {
        t.Fatalf("failed to convert message to bytes: %s", err);
    }

    var rebuiltMessage Message;
    rebuiltMessage.FromBytes(bytes);

    if !slices.Equal(message.Data, rebuiltMessage.Data) {
        t.Error("the rebuilt message data is different from the original");
    }

    if !slices.Equal(message.AesKey, rebuiltMessage.AesKey) {
        t.Error("the rebuilt message AES key is different from the original");
    }
}
