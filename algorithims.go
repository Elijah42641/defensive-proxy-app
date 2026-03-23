package defensiveproxyapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

type request struct {
	Method string `json:"method"`
	URL    string `json:"url"`

	Headers map[string][]string `json:"headers"`
	Body    map[string]string   `json:"body"`
}

var hashesLoaded int
var requestHashes = make(map[string]int)
var backupFileUsed bool
var backupFileNames = make(map[string]string)
var indexOfRequest int
var dupeRequestsIndex = []int{}

func filterOutDupeRequests(fileName string) {
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}

	// load single request, hash, then check if it's in the list of hashes
	decoder := json.NewDecoder(file)

	// Read opening '['
	_, err = decoder.Token()
	if err != nil {
		panic(err)
	}

	// while there are more requests to read
	for decoder.More() {
		if hashesLoaded > 100000 {
			// clear hashes
			hashesLoaded = 0
			// write to file
			backupFileUsed = true
			backupFileName := fileName + "_backup_" + strconv.Itoa(len(backupFileNames)+1)
			backupFileNames[backupFileName] = fileName
			data, err := json.Marshal(requestHashes)
			if err != nil {
				panic(err)
			}
			err = os.WriteFile(backupFileName, data, 0644)
			if err != nil {
				panic(err)
			}
			// clear map
			requestHashes = make(map[string]int)

			continue
		}

		var req request

		err := decoder.Decode(&req)
		if err != nil {
			panic(err)
		}
		// marshall request to bytes so it can be hashed
		requestBytes, err := json.Marshal(req)
		if err != nil {
			panic(err)
		}

		hash := sha256.Sum256(requestBytes)
		// make hash readable
		hashStr := hex.EncodeToString(hash[:])

		if requestHashes[hashStr] >= 0 {
			dupeRequestsIndex = append(dupeRequestsIndex, indexOfRequest)
		} else {
			requestHashes[hashStr] = indexOfRequest
		}
		indexOfRequest++

		hashesLoaded++
	}

	// Read closing ']'
	_, err = decoder.Token()
	if err != nil {
		panic(err)
	}
	file.Close()

	// if there were back up files used make sure there are no dupe hashes
	if backupFileUsed {
		for backupFileName, _ := range backupFileNames {
			backupFile, err := os.Open(backupFileName)
			if err != nil {
				panic(err)
			}
			backupDecoder := json.NewDecoder(backupFile)

			// Read opening '{'
			_, err = backupDecoder.Token()
			if err != nil {
				panic(err)
			}

			for backupDecoder.More() {
				var hashStr = make(map[string]int)
				err := backupDecoder.Decode(&hashStr)
				if err != nil {
					panic(err)
				}

				// hashStr is our hash to compare, idx is the index (to use when deleting dupes)
				for hashStr, idx := range hashStr {
					if _, exists := requestHashes[hashStr]; exists {
						// This is a duplicate, record it
						dupeRequestsIndex = append(dupeRequestsIndex, idx)
					} else {
						// Add it to the main map for tracking
						requestHashes[hashStr] = idx
					}
				}
			}

			// Read closing '}'
			_, err = backupDecoder.Token()
			if err != nil {
				panic(err)
			}
			backupFile.Close()

		}
	}

	// delete backup files
	for backupFileName, _ := range backupFileNames {
		err := os.Remove(backupFileName)
		if err != nil {
			panic(err)
		}

		delete(backupFileNames, backupFileName)
	}

	// remove request at each index that has a dupe

	// we have to re open file because json decoder doesn't allow us to go back and delete items
	temporaryFileName := "temporaryFile"
	counter := 1

	// use simple for instead of recursive function
	for {
		if _, err := os.Stat(temporaryFileName); os.IsNotExist(err) {
			break // file does not exist use this name
		}
		// file exists, generate a new name
		temporaryFileName = fmt.Sprintf("temporaryFile_%d.json", counter)
		counter++
	}

	os.Rename(fileName, temporaryFileName)
	// new file with same name but no dupes
	os.Create(fileName)

	file, err = os.Open(temporaryFileName)
	if err != nil {
		panic(err)
	}
	decoder = json.NewDecoder(file)

	var currentIndex int = 0
	for decoder.More() {
		for _, idx := range dupeRequestsIndex {
			if currentIndex == idx {
				// skip this request
				continue
			} else {
				// append request to file

			}
		}
	}
	// delete old temporary file
	os.Remove(temporaryFileName)
}
