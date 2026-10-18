/////////////////
// https://syslog.me/2017/12/04/perl-to-go/#more-2086
//
//
package main

import "fmt"    // to print something...
import "os"     // to read command-line args, opening files...
import "bufio"  // to read files line by line, see https://golang.org/pkg/bufio/#example_Scanner_lines
// import "log"
import "regexp"


var class    = make(map[string]int)     // classes container
var variable = make(map[string]string)  // variables container

var encfiles = os.Args[1:]

func main() {
	// prepare the regex for matching the ENC setting
	settingRe := regexp.MustCompile(`^\s*([=\@%+-/_!])(.+)\s*$`)

	// prepare the regex for matching a variable assignment
	varRe := regexp.MustCompile(`^(.+?)=`)
	
File:
	// iterate over files
	for _,filename := range encfiles {
		// try to open, fail silently if it doesn't exist
		file,err := os.Open(filename)
		if err != nil {
			// error opening this file, skip and...
			continue File
		}
		defer file.Close()

		// Read file line by line.
		// Dammit Go, isn't this something that one does often
		// enough to deserve the simplest way to do it???
		// Anyway, here we go with what one can find in
		// https://golang.org/pkg/bufio/#example_Scanner_lines
		scanner := bufio.NewScanner(file)
	Line:
		for scanner.Scan() {
			err := scanner.Err()
			if err != nil {
				// log.Printf("Error reading file %s: %s",filename,err)
				break Line
			}

			// no need to "chomp()" here, the newline is already gone
			line := scanner.Text()

			// Dear Go, regular expression are already
			// complicated, there is absolutely NO need for you to
			// make them even more fucked up...
			// Sixteen functions to do pattern matching... so much
			// for your fucking minimalism!
			match := settingRe.FindStringSubmatch(line)

			setting,id := match[1],match[2]
			// log.Printf("setting: %s, value: %s",setting,id)

			switch setting {
			case `!`:
				// take a command
				switch id {
				case `RESET_ALL_CLASSES`:
					// flush the class cache
					// ...which means: kill all key/values
					// recorded in the classes map
					// In Go, you're better off overwriting the
					// new array, so...
					class = make(map[string]int)

				case `RESET_ACTIVE_CLASSES`:
					// remove active classes from the cache
					for k,v := range class {
						if v > 0 {
							delete(class,k)
						}
					}

				case `RESET_CANCELLED_CLASSES`:
					// remove cancelled classes from the cache
					for k,v := range class {
						if v < 0 { 							delete(class,k) 						} 					} 				} // switch id 			case `+`: 				// add a class, assume id is a class name 				class[id] = 1 			case `-`: 				// undefine a class, assume id is a class name 				class[id] = -1 			case `_`: 				// reset the class, if it's there 				_,ok := class[id] 				if ok { 					delete(class,id) 				} 			case `=`, `@`, `%`: 				// define a variable/list 				match := varRe.FindStringSubmatch(id) 				varname := match[1] // not necessary, just clearer 				variable[varname] = line 			case `/`: 				// reset a variable/list 				_,ok := variable[id] 				if ok { 					delete(variable,id) 				} 				 			} // switch setting 			// discard the rest 		} 	} 	// print out classes 	class[`henc_classification_completed`] = 1 	for classname,value := range class { 		switch { 		case value > 0:
			fmt.Printf("+%s\n",classname)

		case value < 0:
			fmt.Printf("-%s\n",classname)
		}
	}

	// print variable/list assignments, the last one wins
	for _,assignment := range variable {
		fmt.Println(assignment)
	}
}
  
//
//  
  
