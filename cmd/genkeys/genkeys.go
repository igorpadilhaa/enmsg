package main

import (
    "github.com/igorpadilhaa/enmsg"

    "os"
    "fmt"
)

func main() {
    args := os.Args;

    if len(args) < 2 {
        fmt.Fprintln(os.Stderr, "ERROR: missing key file path");
        os.Exit(1);
    }

    keyFile := args[1];
    key, err := enmsg.NewKey();
    
    if err != nil {
        fmt.Fprintln(os.Stderr, "ERROR: failed to generate private key");
        fmt.Fprintf(os.Stderr, "ERROR: %s\n", err);
        os.Exit(1);
    }

    if err := enmsg.StoreKey(keyFile, key); err != nil {
        fmt.Fprintln(os.Stderr, "ERROR: failed to store generated key");
        fmt.Fprintf(os.Stderr, "ERROR: %s\n", err);
        os.Exit(1);
    }

    if err != enmsg.StorePublicKey(keyFile + ".pub", &key.PublicKey) {
        fmt.Fprintln(os.Stderr, "ERROR: failed to store generated key public");
        fmt.Fprintf(os.Stderr, "ERROR: %s\n", err);
        os.Exit(1);
    }
}
