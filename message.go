package enmsg

import (
    "encoding/binary"
    "bytes"
)

type Message struct {
    AesKey []byte
    Data []byte
}

func (message *Message) Bytes() ([]byte, error) {
    var buffer []byte;
    header := []int32{
        int32(len(message.AesKey)),
        int32(len(message.Data)),
    };
    
    buffer, err := binary.Append(buffer, binary.BigEndian, header);
    if err != nil {
        return nil, err;
    }

    buffer, err = binary.Append(buffer, binary.BigEndian, message.AesKey);
    if err != nil {
        return nil, err;
    }

    buffer, err = binary.Append(buffer, binary.BigEndian, message.Data);
    return buffer, err;
}

func (message *Message) FromBytes(messageData []byte) error {
    reader := bytes.NewReader(messageData);
    var keySize, dataSize int32;

    err := binary.Read(reader, binary.BigEndian, &keySize);
    if err != nil {
        return err;
    }

    err = binary.Read(reader, binary.BigEndian, &dataSize);
    if err != nil {
        return err;
    }

    key := make([]byte, keySize);
    data := make([]byte, dataSize);

    err = binary.Read(reader, binary.BigEndian, &key);
    if err != nil {
        return err;
    }

    err = binary.Read(reader, binary.BigEndian, &data);
    if err != nil {
        return err;
    }
    
    message.AesKey = key;
    message.Data = data;
    return nil;
}

