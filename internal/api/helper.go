package api

import (
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func MustRespondJSON(w http.ResponseWriter, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Errorf("Failed to marshal JSON: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
