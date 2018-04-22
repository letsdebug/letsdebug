package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"time"

	"sync"

	"strings"

	"github.com/alexzorin/letsdebug"
)

type debugRequest struct {
	Domain     string              `json:"domain"`
	Method     string              `json:"method"`
	Hash       string              `json:"hash"`
	TimeStart  time.Time           `json:"time_start"`
	TimeFinish time.Time           `json:"time_finish"`
	Finished   bool                `json:"finished"`
	Error      error               `json:"error"`
	Problems   []letsdebug.Problem `json:"problems"`
}

var (
	requests      = map[string]debugRequest{}
	requestsMutex = sync.RWMutex{}
)

func main() {
	http.HandleFunc("/new", handleNew)
	http.HandleFunc("/get/", handleGet)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	newRequest := struct {
		Domain string `json:"domain"`
		Method string `json:"method"`
	}{}

	if err := json.NewDecoder(r.Body).Decode(&newRequest); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if newRequest.Domain == "" || newRequest.Method == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	newDebugRequest := debugRequest{
		Domain:    newRequest.Domain,
		Method:    newRequest.Method,
		TimeStart: time.Now(),
	}

	h := sha1.New()
	fmt.Fprintf(h, "%s-%s-%s", newDebugRequest.Domain, newDebugRequest.Method, newDebugRequest.TimeStart)
	newDebugRequest.Hash = fmt.Sprintf("%x", h.Sum(nil))

	requestsMutex.Lock()
	requests[newDebugRequest.Hash] = newDebugRequest
	requestsMutex.Unlock()

	log.Printf("New request: %+v", newDebugRequest)

	go func() {
		probs, err := letsdebug.Check(newDebugRequest.Domain, letsdebug.ValidationMethod(newDebugRequest.Method))
		newDebugRequest.Finished = true
		newDebugRequest.TimeFinish = time.Now()
		if err != nil {
			newDebugRequest.Error = err
		} else {
			newDebugRequest.Problems = probs
		}

		log.Printf("Finished request: %+v", newDebugRequest)

		requestsMutex.Lock()
		requests[newDebugRequest.Hash] = newDebugRequest
		requestsMutex.Unlock()
	}()

	if err := json.NewEncoder(w).Encode(newDebugRequest); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func handleGet(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/") {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	requestedHash := path.Base(r.URL.Path)

	requestsMutex.RLock()
	requestedDebugRequest, ok := requests[requestedHash]
	requestsMutex.RUnlock()

	if !ok {
		log.Printf("Invalid hash: %s", requestedHash)
		http.NotFound(w, r)
		return
	}

	log.Printf("Serving request: %s", requestedHash)

	if err := json.NewEncoder(w).Encode(requestedDebugRequest); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}
