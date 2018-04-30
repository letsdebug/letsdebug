package web

import (
	"encoding/json"
	"log"

	"github.com/letsdebug/letsdebug"
)

type workRequest struct {
	ID     int
	Domain string
	Method string
}

func (s *server) runWorkers(numWorkers int) {
	s.workCh = make(chan workRequest)
	for i := 0; i < numWorkers; i++ {
		go s.work()
	}
}

func (s *server) work() {
	for req := range s.workCh {
		log.Printf("Received notification: %+v", req)

		// Ignore failure
		s.db.Exec(`UPDATE tests SET started_at = CURRENT_TIMESTAMP, status = 'Processing' WHERE id = $1;`, req.ID)

		res, err := letsdebug.Check(req.Domain, letsdebug.ValidationMethod(req.Method))
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

		log.Printf("Test %d complete", req.ID)
	}
}
