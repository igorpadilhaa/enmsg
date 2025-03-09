package main

import (
    "github.com/igorpadilhaa/enmsg"
    "fmt"
    "io"
    "os"
)

func main() {
    args := os.Args;

    if len(args) < 2 {
        fmt.Fprintln(os.Stderr, "ERROR: private key file missing");
        fmt.Printf("Usage: %s <private-key-path> [<input-file-path]\n", args[0]);
        os.Exit(1);
    }
    
    keyFile := args[1];
    var input io.Reader = os.Stdin;
    
    if len(args) >= 3 {
        inputFile := args[2];

        var err error
        file, err := os.Open(inputFile);
        if err != nil {
            fmt.Fprintln(os.Stderr, "ERROR: failed to open input file");
            fmt.Fprintf(os.Stderr, "ERROR: %s\n", err);
            os.Exit(1);
        }
        input = file;
        defer file.Close();
    }

    key, err := enmsg.LoadKey(keyFile);
    if err != nil {
        fmt.Fprintln(os.Stderr, "ERROR: failed to read private key"); 
        fmt.Fprintf(os.Stderr, "ERROR: %s\n", err);
        os.Exit(1);
    }

    data, err := io.ReadAll(input);
    if err != nil {
        fmt.Fprintln(os.Stderr, "ERROR: failed to read input data");
        fmt.Fprintf(os.Stderr, "ERROR: %s\n", err);
        os.Exit(1);
    }

    cipher := enmsg.NewCipher(&key.PublicKey, nil);

    message, err := cipher.Encrypt(data);
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR: failed to encrypt data: %s\n", err);
        os.Exit(1);
    }

    messageBytes, err := message.Bytes();
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR: failed to serialize message: %s\n", err);
        os.Exit(1);
    }
    os.Stdout.Write(messageBytes);
}
