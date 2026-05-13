package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
)

type request struct {
	Timestamp  string              `json:"timestamp"`
	Method     string              `json:"method"`
	URL        string              `json:"url"`
	RemoteAddr string              `json:"remoteAddr"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"bodyBase64"`
}

// map of all the request hashes so it persists through each loop
var requestHashes = make(map[string]int)
var backupFileUsed bool
var backupFileNames = make(map[string]string)
var indexOfRequest int
var dupeRequestsIndex = []int{}

func FilterOutDupeRequests(fileName string) error {
	log.Printf("[FilterOutDupeRequests] START: fileName=%s", fileName)

	seenHashes := make(map[string]struct{})

	// --- Load hashes from backups first ---
	if backupFileUsed {
		log.Printf("[FilterOutDupeRequests] Processing %d backup files", len(backupFileNames))

		for backupFileName := range backupFileNames {
			log.Printf("[FilterOutDupeRequests] Reading backup: %s", backupFileName)

			data, err := os.ReadFile(backupFileName)
			if err != nil {
				return err
			}

			decoder := json.NewDecoder(bytes.NewReader(data))

			for decoder.More() {
				var hashMap map[string]int
				if err := decoder.Decode(&hashMap); err != nil {
					return err
				}

				for hash := range hashMap {
					seenHashes[hash] = struct{}{}
				}
			}
		}
	}

	// --- Prepare temp file ---
	tempFileName := fileName + ".tmp"

	inputFile, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	outputFile, err := os.Create(tempFileName)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	scanner.Buffer(make([]byte, 1024), 1024*1024) // allow larger lines

	total := 0
	written := 0
	skipped := 0

	for scanner.Scan() {
		line := scanner.Text()
		total++

		if line == "" {
			continue
		}

		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			log.Printf("[FilterOutDupeRequests] Skipping invalid JSON at line %d: %v", total, err)
			continue
		}

		normalized, err := json.Marshal(req)
		if err != nil {
			return err
		}

		hash := sha256.Sum256(normalized)
		hashStr := hex.EncodeToString(hash[:])

		if _, exists := seenHashes[hashStr]; exists {
			skipped++
			continue
		}

		seenHashes[hashStr] = struct{}{}

		if _, err := outputFile.WriteString(line + "\n"); err != nil {
			return err
		}

		written++
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// --- Replace original file ---
	if err := os.Rename(tempFileName, fileName); err != nil {
		return err
	}

	// --- Cleanup backups ---
	for backupFileName := range backupFileNames {
		log.Printf("[FilterOutDupeRequests] Removing backup: %s", backupFileName)
		os.Remove(backupFileName)
		delete(backupFileNames, backupFileName)
	}

	log.Printf("[FilterOutDupeRequests] COMPLETE: total=%d written=%d skipped=%d",
		total, written, skipped)

	return nil
}
