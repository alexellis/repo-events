package function

import (
	"bytes"
	"fmt"
	"net/http"
	"os"

	"github.com/google/go-github/v40/github" // with go modules enabled (GO111MODULE=on or outside GOPATH)
	handler "github.com/openfaas/templates-sdk/go-http"
)

// Handle a function invocation
func Handle(req handler.Request) (handler.Response, error) {

	webhookSecretKey, err := os.ReadFile("/var/openfaas/secrets/webhook-secret")
	if err != nil {
		return handler.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       []byte(fmt.Sprintf("Error reading webhook secret: %s", err)),
		}, err
	}

	payload, err := github.ValidatePayloadFromBody(req.Header.Get("Content-Type"),
		bytes.NewBuffer(req.Body),
		req.Header.Get(github.SHA256SignatureHeader),
		webhookSecretKey)

	if err != nil {
		return handler.Response{
			StatusCode: http.StatusBadRequest,
			Body:       []byte(fmt.Sprintf("Error validating payload: %s", err.Error())),
		}, err
	}

	eventType := req.Header.Get(github.EventTypeHeader)
	event, err := github.ParseWebHook(req.Header.Get(eventType), payload)
	if err != nil {
		return handler.Response{
			StatusCode: http.StatusBadRequest,
			Body:       []byte(fmt.Sprintf("Error parsing webhook: %s", err.Error())),
		}, err
	}

	switch event := event.(type) {
	case *github.IssueCommentEvent:
		fmt.Printf("Issue comment body: %s\n", event.GetComment().GetBody())
	default:
		return handler.Response{
			StatusCode: http.StatusBadRequest,
			Body:       []byte(fmt.Sprintf("Event type not supported: %s", eventType)),
		}, nil
	}

	return handler.Response{
		Body:       []byte("Accepted webhook"),
		StatusCode: http.StatusAccepted,
	}, err
}
