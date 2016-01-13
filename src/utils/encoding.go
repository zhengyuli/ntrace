package utils

import (
	"bytes"
	"encoding/gob"
)

func Encode(data interface{}) (encData []byte, err error) {
    buf := bytes.NewBuffer(nil)
    enc := gob.NewEncoder(buf)

    err = enc.Encode(data)
    if err != nil {
        encData = nil
    } else {
		encData = buf.Bytes()
	}

    return
}

func Decode(encData []byte, data interface{}) (error) {
    dec := gob.NewDecoder(bytes.NewBuffer(encData))
    return dec.Decode(data)
}
