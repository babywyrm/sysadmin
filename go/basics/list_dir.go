//obvi
//

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"flag"
)

func listdir() {

	dirpath := flag.String("directory", "/foo", "The directory we want to list files in")

	flag.Parse()

	fmt.Println("directory:", *dirpath)

	file, err := ioutil.ReadDir(*dirpath)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range file {
		fmt.Println(f.Name())
	}
}

func main() {

	listdir()
}

//
//
