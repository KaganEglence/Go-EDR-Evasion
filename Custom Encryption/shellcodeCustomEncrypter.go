package main

import (
	"encoding/hex"
	"fmt"
)

func encrypter(data []byte, key byte) {
	for i := 0; i < len(data); i++ {
		data[i] += key
	}
}

func decrypter(data []byte, key byte) {
	for i := 0; i < len(data); i++ {
		data[i] -= key
	}
}

func addPrefix(data []byte, keyChar byte) []byte {
	prefixedData := make([]byte, len(data)*2)

	for i := 0; i < len(data); i++ {
		prefixedData[i*2] = keyChar
		prefixedData[i*2+1] = data[i]
	}

	return prefixedData
}

func removePrefix(data []byte, keyChar byte) []byte {
	unprefixedData := make([]byte, len(data)/2)

	for i := 0; i < len(unprefixedData); i++ {
		unprefixedData[i] = data[i*2+1]
	}

	if unprefixedData[len(unprefixedData)-1] == keyChar {
		unprefixedData = unprefixedData[:len(unprefixedData)-1]
	}

	return unprefixedData
}

func main() {
	shellcodeValue := []byte{0xfc, ..., 0xd5}

	key := 0x07
	keyChar := byte('k')

	fmt.Println("Original Shellcode:", shellcodeValue, hex.EncodeToString(shellcodeValue))

	encrypter(shellcodeValue, byte(key))
	prefixedData := addPrefix(shellcodeValue, keyChar)
	encyptedHex := hex.EncodeToString(prefixedData)
	fmt.Println("Encrypted Shellcode:", encyptedHex)

	decryptedShellcode, _ := hex.DecodeString(encyptedHex)
	decrypter(decryptedShellcode, byte(key))
	fmt.Println("Decrypted Shellcode (Before Remove Prefix):", hex.EncodeToString(decryptedShellcode))

	unprefixedData := removePrefix(decryptedShellcode, keyChar)
	fmt.Println("Decrypted Shellcode (After Remove Prefix):", unprefixedData, hex.EncodeToString(unprefixedData))
}
