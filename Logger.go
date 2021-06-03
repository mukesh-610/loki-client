package main

import (
	"log"
	"os"
	"path/filepath"
)

var logFile *os.File

func setupLogger() {
	log.Println(`Loki starting up...`)

	filePath, err := os.Executable()
	if err != nil {
		log.Fatal(`Cannot get file path!`)
	}

	folder := filepath.Dir(filePath)
	logFile, err = os.OpenFile(folder+string(os.PathSeparator)+`Loki.log`, os.O_RDWR|os.O_CREATE|os.O_APPEND,
		0666)
	if err != nil {
		log.Fatal(`Cannot open log file!`)
	}

	log.SetOutput(logFile)
	log.Println(`Loki has successfully started up.`)
}

func closeLogger() {
	err := logFile.Close()
	if err != nil {
		log.SetOutput(os.Stderr)
		log.Fatal(`There was an error closing the log file!`)
	}
}
