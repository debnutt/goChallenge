package main

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
	"strings"
	"strconv"
	"os/signal"
	"os"
	"syscall"
)

var passwords = make(map[int][]byte)
var jobCount = 0
var numHashRequests int = 0
var totalProcessingTime int64 = 0

// Function execution time tracker in ms
func timeTracker(start time.Time, name string) {
    totalProcessingTime += int64(time.Since(start).Nanoseconds() / 1000);
}

// Delay the hashing of the password
func delayedPasswordHash(password string, jobId int) {
	time.Sleep(time.Second * 5)
	passwords[jobId] = hashPassword(password)
}

// SHA512 password using sha512 algorithm
func hashPassword(password string) []byte {
		sha_512 := sha512.New()
		sha_512.Write([]byte(password))
	return sha_512.Sum(nil)
}

// Base64 encode a password
func getEncodedPassword(password []byte) string {
	return string(base64.StdEncoding.EncodeToString(password))
}

// Get the password from the request body
func getPassword(r *http.Request) (string) {
	body, _ := ioutil.ReadAll(r.Body)
	data := strings.Split(string(body), "=")
	password := data[1]
	return password
}

func hashPasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Time how long this request takes
	defer timeTracker(time.Now(), "hashPasswordHandler")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Increment the number /hash requests
	numHashRequests++

	// Read password
	jobCount++
	password := getPassword(r)

	// Sha512 hash it 5 seconds later and store it in the passwords map by a job identifier
	go delayedPasswordHash(password, jobCount)

	// Immediately return job identifier
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "%d\n", jobCount)
}

func getJobByIdHandler(w http.ResponseWriter, r *http.Request) {
	// Time how long this request takes
	defer timeTracker(time.Now(), "getJobByIdHandler")

	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Increment the number /hash requests
	numHashRequests++

	// Read the job ID
	id := strings.TrimPrefix(r.URL.Path, "/hash/")

	// Get the corresponding password out of the map
	idAsInt, err := strconv.Atoi(id)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	password := passwords[idAsInt]

	// base64 encode it and return it
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s\n", getEncodedPassword(password))
}

func showStatsHandler(w http.ResponseWriter, r *http.Request) {
	// Output JSON responsewith the total number of hash requests and the average time each request
	// takes in ms (averageProcessingTime = totalProcessingTime / numHashRequests)
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	stats := make(map[string]int)
	stats["total"] = numHashRequests
	stats["average"] = int(totalProcessingTime / int64(numHashRequests))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
 }

func main() {
	// Shutdown code -- handle existing requests, do not allow new during shutdown

	http.HandleFunc("/hash", hashPasswordHandler)
	http.HandleFunc("/hash/", getJobByIdHandler)
	http.HandleFunc("/stats", showStatsHandler)

	http.ListenAndServe(":8080", nil)

	signalChan := make(chan os.Signal, 1)
	done := make(chan bool)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		for _ = range signalChan {
			fmt.Println("\nStopping application...\n")
			done <- true
		}
	}()
	<-done
}
