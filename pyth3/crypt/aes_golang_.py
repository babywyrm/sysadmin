//
//
// https://gist.githubusercontent.com/STGDanny/03acf29a90684c2afc9487152324e832/raw/e243c5b0b6edeba1e3c423dd035c23daea102695/AES_Example.go
//
//

/*
*	FILE			: AES_Example.go
*	PROJECT			: INFO-1340 - Block Ciphers
*	PROGRAMMER		: Daniel Pieczewski, ref: https://github.com/mickelsonm
*	FIRST VERSION		: 2020-04-12
*	DESCRIPTION		:
*		The function(s) in this file make up example code for encryption and decryption of a block of text
*		using the Golang standard library AES implementation using the Cipher Feedback mode of encryption (CFB). 
*		DISCLAIMER: There is no way that this a secure implementation of AES. This is only for my personal learning.
*		So help you God if this ends up in some commercial application.
 */
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	cipherKey := []byte("asuperstrong32bitpasswordgohere!") //32 bit key for AES-256
	//cipherKey := []byte("asuperstrong24bitpasswor") //24 bit key for AES-192
	//cipherKey := []byte("asuperstrong16bi") //16 bit key for AES-128

	reader := bufio.NewReader(os.Stdin)

	var message string

	//IF no command line argument is given:
	if len(os.Args) != 2 {
		//Get user input
		fmt.Printf("\n\tNo command line argument found, getting user input\n")
		fmt.Printf("\tEnter a string to test: ")
		message, _ = reader.ReadString('\n')
	} else { //Make the message equal to the command line argument
		message = os.Args[1]
	}

	//Encrypt the text:
	encrypted, err := encrypt(cipherKey, message)

	//IF the encryption failed:
	if err != nil {
		//Print error message:
		log.Println(err)
		os.Exit(-2)
	}

	//Print the key and cipher text:
	fmt.Printf("\n\tCIPHER KEY: %s\n", string(cipherKey))
	fmt.Printf("\tENCRYPTED: %s\n", encrypted)

	//Decrypt the text:
	decrypted, err := decrypt(cipherKey, encrypted)

	//IF the decryption failed:
	if err != nil {
		log.Println(err)
		os.Exit(-3)
	}

	//Print re-decrypted text:
	fmt.Printf("\tDECRYPTED: %s\n\n", decrypted)
}

/*
 *	FUNCTION		: encrypt
 *	DESCRIPTION		:
 *		This function takes a string and a cipher key and uses AES to encrypt the message
 *
 *	PARAMETERS		:
 *		byte[] key	: Byte array containing the cipher key
 *		string message	: String containing the message to encrypt
 *
 *	RETURNS			:
 *		string encoded	: String containing the encoded user input
 *		error err	: Error message
 */
func encrypt(key []byte, message string) (encoded string, err error) {
	//Create byte array from the input string
	plainText := []byte(message)

	//Create a new AES cipher using the key
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		return
	}

	//Make the cipher text a byte array of size BlockSize + the length of the message
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	//iv is the ciphertext up to the blocksize (16)
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	//Encrypt the data:
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//Return string encoded in base64
	return base64.RawStdEncoding.EncodeToString(cipherText), err
}

/*
 *	FUNCTION		: decrypt
 *	DESCRIPTION		:
 *		This function takes a string and a key and uses AES to decrypt the string into plain text
 *
 *	PARAMETERS		:
 *		byte[] key	: Byte array containing the cipher key
 *		string secure	: String containing an encrypted message
 *
 *	RETURNS			:
 *		string decoded	: String containing the decrypted equivalent of secure
 *		error err	: Error message
 */
func decrypt(key []byte, secure string) (decoded string, err error) {
	//Remove base64 encoding:
	cipherText, err := base64.RawStdEncoding.DecodeString(secure)

	//IF DecodeString failed, exit:
	if err != nil {
		return
	}

	//Create a new AES cipher with the key and encrypted message
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		return
	}

	//IF the length of the cipherText is less than 16 Bytes:
	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	//Decrypt the message
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), err
}

//
//
