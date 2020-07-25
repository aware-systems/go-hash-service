package main

import (
	"crypto/sha512"
	"fmt"
)

func main() {
	hash_string("this is a strong")
	hash_string("this is a different strong")
	hash_string("this is a stiong")
}

func hash_string(passwd string) string {
	h := sha512.New()
	h.Write([]byte(passwd))
	hsum := h.Sum(nil)
	fmt.Println(passwd)
	fmt.Printf("%x\n", hsum)
	return string([]byte(hsum))
}
