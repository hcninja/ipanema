/*
   Copyright 2018 <Jose Gonzalez Krause - josef@hackercat.ninja>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	// log "github.com/sirupsen/logrus"
)

// Unzip will decompress a zip archive, moving all files and folders
// within the zip file (parameter 1) to an output directory (parameter 2).
func Unzip(src string, dest string) ([]string, error) {
	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {

		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}
		defer rc.Close()

		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)
		filenames = append(filenames, f.Name)

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
		} else {
			// Make File
			if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				return filenames, err
			}

			outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return filenames, err
			}

			_, err = io.Copy(outFile, rc)

			// Close the file without defer to close before next iteration of loop
			outFile.Close()

			if err != nil {
				return filenames, err
			}
		}
	}

	return filenames, nil
}

// PrettyPrinter prints the extracted info in a fancy way
func PrettyPrinter(ar *AnalysisResult) {
	log.Info("Available plist files")
	for _, plist := range ar.Plists {
		fmt.Println("\t\t" + plist)
	}

	log.Info("Available certificates")
	for _, cert := range ar.CertFiles {
		fmt.Println("\t\t" + cert)
	}

	//	Print out the analysis info
	log.Info("IPA metadata")
	log.Infof("[Number of files] %d", ar.NumberOfFiles)
	log.Infof("[File name] %s", ar.FileName)
	log.Infof("[App name] %s", ar.AppName)
	log.Infof("[Version] %s", ar.Version)
	log.Infof("[File size] %dK (%dMB)", ar.FileSize, ar.FileSize/(1024*1024))
	log.Infof("[MD5] %s", ar.MD5)
	log.Infof("[SHA1] %s", ar.SHA1)
	log.Infof("[SHA256] %s", ar.SHA256)
	log.Infof("[Bundle name] %s", ar.BundleName)
	log.Infof("[SDK name] %s", ar.SDKName)
	log.Infof("[Platform version] %s", ar.PlatformVersion)
	log.Infof("[Main OS version] %s", ar.MainOSVersion)
	log.Info("[App Transport Security]")
	for k, v := range ar.ATSec {
		fmt.Printf("\t\t %s: %t\n", k, v)
	}
	log.Infof("[Allow Stack Execution flag] %t", ar.AllowStackExecution)
	log.Infof("[Root Safe flag] %t", ar.RootSafe)
	log.Infof("[SetUID safe flag] %t", ar.SetuidSafe)
	log.Infof("[Is PIE compiled] %t", ar.IsPIE)
	log.Infof("[No Heap execution] %t", ar.NoHeapExecution)
	log.Info("[Files with interesting data]")
	for k, v := range ar.WorthyEggs {
		fmt.Printf("\t\t %s:\n", k)
		for _, element := range v {
			fmt.Printf("\t\t\t %s\n", element)
		}
	}
}

// FileDump prints the extracted info in a fancy way
func FileDump(ar *AnalysisResult) {
	baseDir := filepath.Join(ar.ProjDir, "analysisResult")

	if _, err := os.Stat(baseDir); err != nil {
		if err := os.Mkdir(baseDir, 0777); err != nil {
			checkError(err)
		}
	}

	// Libs dump
	NewFile(ar.ImpLibs, baseDir, "imported_libraries.txt")

	// Symbols dump
	NewFile(ar.ImpSyms, baseDir, "imported_symbols.txt")

	// Symbols table dump
	NewFile(ar.SymTab, baseDir, "symbols_table.txt")

	// Strings dump
	NewFile(ar.Strings, baseDir, "strings.txt")

	// Paths dump
	NewFile(ar.DisclosedPaths, baseDir, "disclosed_paths.txt")

	// URLs dump
	NewFile(ar.URLs, baseDir, "urls.txt")

	jsonBuf, err := json.MarshalIndent(ar, "", "\t")
	checkError(err)

	ioutil.WriteFile(
		filepath.Join(baseDir, "analysis.json"),
		jsonBuf,
		0660,
	)
}

// SecurityAnalysis evaluates some risky issues and explains why
func SecurityAnalysis(ar *AnalysisResult) {

}

// ===========
// = Helpers =
// ===========

// NewFile creates a new file with the content dump
func NewFile(items []string, baseDir, fileName string) {
	var buff []byte

	for _, line := range items {
		lb := []byte(line)
		lb = append(lb, 0x0a)
		buff = append(buff, lb...)
	}

	ioutil.WriteFile(
		filepath.Join(baseDir, fileName),
		buff,
		0660,
	)
}
