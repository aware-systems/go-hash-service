package main

import (
	"crypto/sha512"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type HashedID struct {
	ID     int
	Passwd string
	Hval   string
}

type StatsResponse struct {
	Total    int     `json:"total"`    // number of requests to /hash
	Average  int     `json:"average"`  // avg time serving hashen in ms
	Runtimes []int64 `json:"runtimes"` // runtime array
}

var (
	shuttingDown bool
	hashen       []HashedID
	hashMutex    sync.Mutex
	runtimes     []int64
)

func populate_hash(idx int, ctv string) {
	time.Sleep(5 * time.Second)
	hashen[idx].Hval = hash_string(ctv)
}

func average_runtimes() int {
	var sum int64 = 0

	if len(runtimes) == 0 {
		return 0
	}

	for _, i := range runtimes {
		sum += i
	}

	return int(sum) / len(runtimes)
}

// Hijacks, flushes and closes the client connection
func expunge_connection(w http.ResponseWriter) {
	// TODO BUG: what to do if Flusher doesn't exist
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	hj, _ := w.(http.Hijacker)
	con, _, _ := hj.Hijack()
	con.Close()
}

func response_wrapper(w http.ResponseWriter, ct string, content string) {
	w.Header().Add("Content-Length", fmt.Sprintf("%d", len(content)))
	w.Header().Add("Content-Type", ct)
	w.WriteHeader(200)
	w.Write([]byte(content))
}

// start here
func main() {
	listenPort := flag.Int("port", 8080, "listen on port")
	listenAddr := flag.String("address", "localhost", "address to listen for")
	flag.Parse()

	// hash - return SHA52 of given password parameter
	http.HandleFunc("/hash", func(w http.ResponseWriter, req *http.Request) {
		var requestStart = time.Now().UnixNano()
		hashMutex.Lock()

		var inputPwd = "abcdefg..."
		var newID = len(hashen)

		thisHash := HashedID{ID: newID, Passwd: inputPwd, Hval: ""}
		hashen = append(hashen, thisHash)
		hashMutex.Unlock()

		response_wrapper(w, "text/plain", fmt.Sprintf("%d", newID+1))
		expunge_connection(w)

		runtimes = append(runtimes, time.Now().UnixNano()-requestStart)
		defer populate_hash(newID, inputPwd)
	})

	// stats - return JSON object containing total and average
	http.HandleFunc("/stats", func(w http.ResponseWriter, req *http.Request) {
		asOfNow := StatsResponse{Total: len(hashen), Average: average_runtimes(), Runtimes: runtimes}
		jsonStr, err := json.Marshal(asOfNow)

		if err == nil {
			response_wrapper(w, "application/json", string(jsonStr))
		} else {
			fmt.Fprintln(w, "JSON error:", err)
		}
	})

	// shutdown - graceful exit
	http.HandleFunc("/shutdown", func(w http.ResponseWriter, req *http.Request) {
		// TODO
	})

	fmt.Printf("Listening on %s:%d", *listenAddr, *listenPort)
	fmt.Printf("%v", http.ListenAndServe(fmt.Sprintf("%s:%d", *listenAddr, *listenPort), nil))
}

func hash_string(passwd string) string {
	h := sha512.New()
	h.Write([]byte(passwd))
	hsum := h.Sum(nil)
	return string([]byte(hsum))
}
