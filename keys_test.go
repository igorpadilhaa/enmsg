package enmsg 

import "testing"

func TestKeyStoring(t *testing.T) {
    t.Parallel()

    tmpPath := t.TempDir();
    keyPath := tmpPath + "/key_gen_test.key";

    originalKey, err := NewKey();
    if err != nil {
        t.Fatal("Failed to generate key:", err);
    }

    if err := StoreKey(keyPath, originalKey); err != nil {
        t.Fatal("Failed to write key file:", err);
    }

    loadedKey, err := LoadKey(keyPath);
    if err != nil {
        t.Fatal("Failed to read key file:", err);
    }

    if !originalKey.Equal(loadedKey) {
        t.Error("the stored key does not match with the original key");
    }
}

func TestPublicKeyEncoding(t *testing.T) {
    t.Parallel();

    originalKey, err := NewKey();
    if err != nil {
        t.Fatal("failed to generate key:", err);
    }
    keyData := EncodePublicKey(&originalKey.PublicKey);
    
    decodedKey, err := DecodePublicKey(keyData);
    if err != nil {
        t.Fatal("failed to decode public key:", err);
    }

    if !originalKey.PublicKey.Equal(decodedKey) {
        t.Fatal("decoded key doesn't match original key");
    }
}
