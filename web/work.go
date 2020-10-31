package web

import (
	"encoding/json"
	"log"
	"sync/atomic"

	"github.com/letsdebug/letsdebug"
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
	for req := range s.workCh {
		log.Printf("Received notification: %+v", req)
		atomic.AddInt32(&s.busyWorkers, 1)

		// Ignore failure
		_, _ = s.db.Exec(`UPDATE tests SET started_at = CURRENT_TIMESTAMP, status = 'Processing' WHERE id = $1;`, req.ID)

		res, err := letsdebug.CheckWithOptions(req.Domain, letsdebug.ValidationMethod(req.Method), letsdebug.Options{
			HTTPExpectResponse: req.Options.HTTPExpectResponse,
			HTTPRequestPath:    req.Options.HTTPRequestPath,
		})
		result := resultView{Problems: res}
		if err != nil {
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
