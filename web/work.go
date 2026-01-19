package web

import (
	"encoding/json"
	"log"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/letsdebug/letsdebug"
)

var (
	testsRun = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "letsdebug",
			Name:      "tests_run_total",
			Help:      "The total number of processed tests",
		},
		[]string{"method"})
	testsFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "letsdebug",
			Name:      "tests_failed_total",
			Help:      "The total number of tests encountering internal errors",
		},
		[]string{"method"})
)

type workRequest struct {
	ID      int
	Domain  string
	Method  string
	Options options
}

func (s *server) runWorkers(numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		go s.work()
	}
}

func (s *server) work() {
	defer func() {
		log.Fatalln("worker exited abnormally")
	}()
	for req := range s.workCh {
		log.Printf("Received notification: %+v", req)
		atomic.AddInt32(&s.busyWorkers, 1)

		// Ignore failure
		_, _ = s.db.Exec(`UPDATE tests SET started_at = CURRENT_TIMESTAMP, status = 'Processing' WHERE id = $1;`, req.ID)

		method := letsdebug.ValidationMethod(req.Method)
		res, err := letsdebug.CheckWithOptions(req.Domain, method, letsdebug.Options{
			HTTPExpectResponse: req.Options.HTTPExpectResponse,
			HTTPRequestPath:    req.Options.HTTPRequestPath,
		})
		isOk := false
		if err == nil {
			isOk = true
			for _, p := range res {
				if p.Severity != letsdebug.SeverityInfo && p.Severity != letsdebug.SeverityDebug {
					isOk = false
					break
				}
			}
		} else {
			isOk = false
		}
		testsRun.With(prometheus.Labels{"method": string(method)}).Inc()
		result := resultView{Problems: res, IsOk: isOk}
		if err != nil {
			testsFailed.With(prometheus.Labels{"method": string(method)}).Inc()
			result.Error = err.Error()
		}

		strResult, _ := json.Marshal(result)
		if _, err := s.db.Exec(`UPDATE tests SET completed_at = CURRENT_TIMESTAMP, status = 'Complete', result = $2 WHERE id = $1;`,
			req.ID, string(strResult)); err != nil {
			log.Printf("Error storing test %d result: %v", req.ID, err)
			continue
		}

		atomic.AddInt32(&s.busyWorkers, -1)
		log.Printf("Test %d complete", req.ID)
	}
}
