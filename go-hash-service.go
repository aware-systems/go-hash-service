package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"time"
)

var (
	hashen     []HashedID // contains the generated HashedIDs
	hashMutex  sync.Mutex // used when updating hashen
	runtimes   []int      // microsecond runtimes for /hash* requests
	done       chan bool
	quit       chan os.Signal
	httpServer http.Server
)

// Hash entities stored in 'hashen' array
type HashedID struct {
	ID   int    // hashen[offset] + 1
	Hval string // value to expose in /hash/... response
}

// json object exposed via GET /stats
type StatsResponse struct {
	Total   int `json:"total"`   // number of requests to /hash
	Average int `json:"average"` // avg time serving hashen in ms
}

// start here
func main() {
	listenPort := flag.Int("port", 8080, "listen on port")
	listenAddr := flag.String("address", "localhost", "address to listen for")
	flag.Parse()

	httpRouter := http.NewServeMux()

	listenOn := fmt.Sprintf("%s:%d", *listenAddr, *listenPort)
	httpServer := &http.Server{
		Addr:         listenOn,
		Handler:      httpRouter,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  5 * time.Second}

	// Avoid keepalives when we are manually closing connections like this.
	httpServer.SetKeepAlivesEnabled(false)

	// hash/ID - return pre-calculated sha512 hash given a secret key (ID #)
	httpRouter.HandleFunc("/hash/", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" {
			httpNotAllowed(w)
			return
		}

		inputID, e := strconv.Atoi(string(req.URL.Path)[6:]) // 6 == len("/hash/")
		if e != nil {
			http.NotFound(w, req)
			return
		}

		// Make sure the requested ID is valid and return 404 if not.
		if inputID > 0 && inputID <= len(hashen) && hashen[inputID-1].Hval != "" {
			fmt.Println(hashen[inputID-1].Hval)
			responseWrapper(w, "text/plain", fmt.Sprintf("%s\n", hashen[inputID-1].Hval), http.StatusOK)
		} else {
			http.NotFound(w, req)
		}
	})

	// hash - return SHA52 of given password parameter
	httpRouter.HandleFunc("/hash", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			httpNotAllowed(w)
			return
		}

		requestStart := time.Now().UnixNano()
		hashMutex.Lock()

		inputPwd := req.PostFormValue("password")
		if len(inputPwd) == 0 {
			httpPasswordError(w)
			hashMutex.Unlock()
			return
		}

		newID := len(hashen)
		thisHash := HashedID{ID: newID, Hval: ""}
		hashen = append(hashen, thisHash)

		responseWrapper(w, "text/plain", fmt.Sprintf("%d\n", newID+1), http.StatusOK)

		// deferred populateHash blocks connections, force flush and disconnect
		expungeConnection(w)

		requestEnd := time.Now().UnixNano()
		runtime := int(requestEnd - requestStart)

		if runtime > 0 { // BUG: this happens sometimes
			runtimes = append(runtimes, runtime)
		}

		hashMutex.Unlock()
		defer populateHash(newID, inputPwd)
	})

	// stats - return JSON object containing total and average
	httpRouter.HandleFunc("/stats", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" {
			httpNotAllowed(w)
			return
		}

		asOfNow := StatsResponse{Total: len(hashen), Average: calculateAverage()}
		jsonStr, err := json.Marshal(asOfNow)

		if err == nil {
			responseWrapper(w, "application/json", string(jsonStr), http.StatusOK)
		} else {
			fmt.Fprintln(w, "JSON error:", err)
		}
	})

	// shutdown - graceful exit
	httpRouter.HandleFunc("/shutdown", func(w http.ResponseWriter, req *http.Request) {
		// TODO BUG: Windows cannot handle graceful shutdown, find a better way
		process, _ := os.FindProcess(os.Getpid())
		responseWrapper(w, "text/plain", "Goodbye!", http.StatusOK)

		expungeConnection(w) // necessary because windows

		if runtime.GOOS == "windows" {
			process.Signal(os.Kill)
		} else {
			process.Signal(os.Interrupt)
		}
	})

	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		fmt.Println("Server is shutting down...")
		gracefulShutdown()
		close(done)
	}()

	fmt.Println("Listening on", fmt.Sprintf("%s:%d", *listenAddr, *listenPort))
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Could not listen on %s: %v\n", listenAddr, err)
		}
	}()

	<-done
	fmt.Println("Server stopped")
}

// render 500 errors
func httpPasswordError(w http.ResponseWriter) {
	responseWrapper(w, "text/plain", "Invalid password entry.", http.StatusBadRequest)
}

// render 405 Method Not Allowed error
func httpNotAllowed(w http.ResponseWriter) {
	responseWrapper(w, "text/plain", "Method not allowed.", http.StatusMethodNotAllowed)
}

// SHUTDOWN
func gracefulShutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		fmt.Println(err)
	}

}

// hash a given string and return Base64 encoded SHA512 hash
func hashPassword(passwd string) string {
	// Calculate the sha512
	h := sha512.New()
	h.Write([]byte(passwd))
	hsum := h.Sum(nil)

	// Return encoded version
	encoded := base64.StdEncoding.EncodeToString(hsum)
	return encoded
}

func populateHash(idx int, ctv string) {
	// 5 second delay is part of requirements.
	time.Sleep(5 * time.Second)

	hashMutex.Lock()
	defer hashMutex.Unlock()

	hashen[idx].Hval = hashPassword(ctv)
}

func calculateAverage() int {
	var sum int

	if len(runtimes) == 0 { // avoid divisoin by zero when nothing has yet hashed
		return 0
	}

	for _, i := range runtimes {
		sum += i
	}

	return sum / len(runtimes)
}

// Hijacks, flushes and closes the client connection
func expungeConnection(w http.ResponseWriter) {
	// TODO BUG: Double-check Flusher is available in future protocols
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	hj, _ := w.(http.Hijacker)
	con, _, _ := hj.Hijack()
	con.Close()
}

// Generic content / output wrapper
func responseWrapper(w http.ResponseWriter, ct string, content string, statusCode int) {
	w.Header().Add("Content-Length", fmt.Sprintf("%d", len(content)))
	w.Header().Add("Content-Type", ct)
	w.WriteHeader(statusCode)
	w.Write([]byte(content))
}
