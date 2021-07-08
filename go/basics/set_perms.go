//obvi
//
//

package main 

import (
		"os"
		"log"
		"fmt"
		"flag"

)


func main()	{

		file_path := flag.String("filepath", "file.csv", "The file we are changing the permissions for")

		flag.Parse()

		fmt.Println("Filepath is :", *file_path)

		// Change file permissions
		if err := os.Chmod(*file_path, 0444); err != nil {
				log.Fatal(err)
		}

		// Get new file permissions and print
		info, err := os.Stat(*file_path)
			if err != nil {
				fmt.Println("Error", err)
				os.Exit(1)
			}
		mode := info.Mode()
		fmt.Print(*file_path," permissions are now ", ":", mode)

}
