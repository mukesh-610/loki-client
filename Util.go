package main

import (
	"golang.org/x/sys/windows/registry"
	"log"
)

func openRegistryKey(hive registry.Key, path string) registry.Key {
	key, _, err := registry.CreateKey(hive, path, registry.ALL_ACCESS)
	if err != nil {
		log.Fatal(`There was an error opening the registry key: `, err)
	}
	return key
}

func closeRegistryKey(key registry.Key) {
	err := key.Close()
	if err != nil {
		log.Fatal(`There was an error closing the registry key.`)
	}
}

func getRegistryValue(hive registry.Key, path string, value string) (string, uint32, error) {
	key := openRegistryKey(hive, path)
	retVal, retType, err := key.GetStringValue(value)
	closeRegistryKey(key)
	return retVal, retType, err
}

func setRegistryValue(hive registry.Key, path string, name string, value string) error {
	key := openRegistryKey(hive, path)
	err := key.SetStringValue(name, value)
	closeRegistryKey(key)
	return err
}
