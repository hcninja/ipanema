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
	"flag"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	// https://godoc.org/github.com/DHowett/go-plist
)

var (
	version   = "dev"
	buildTime = ""
	ipaFlag   string
)

var log = logrus.New()

func init() {
	// log.SetLevel(log.DebugLevel)
	// log.SetOutput(os.Stderr)
	// log.SetFormatter(&prefixed.TextFormatter{})
	formatter := &prefixed.TextFormatter{
		FullTimestamp: true,
	}

	log.Formatter = formatter
	log.Level = logrus.DebugLevel
	log.SetOutput(os.Stdout)

	flag.StringVar(&ipaFlag, "ipa", "", "Select the ipa to analyze")
	flag.Parse()
}

func main() {
	log.Debugf("Starting ipanema v%s build (%s)", version, buildTime)

	if ipaFlag == "" {
		log.Error("Please, read the help info:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var ar AnalysisResult

	fi, err := os.Stat(ipaFlag)
	checkError(err)
	ar.FileName = fi.Name()
	ar.FileSize = fi.Size()

	ar.HashCalculator(ipaFlag)

	ar.ProjDir = filepath.Join(os.TempDir(), strings.Replace(ar.FileName, ".", "_", -1))

	log.Debugf("Using the temporary folder: %s", ar.ProjDir)
	ar.AppFiles, err = Unzip(ipaFlag, ar.ProjDir)
	checkError(err)

	// foo := strings.Split(ar.AppFiles[1], "/")[1]
	ar.AppContainer = FindAppContainer(ar.AppFiles)
	log.Debugf("App container: %s", ar.AppContainer)

	ar.NumberOfFiles = len(ar.AppFiles)
	log.Debugf("Decompressed a total of %d files", ar.NumberOfFiles)

	log.Debug("Searching for interesting files")
	ar.GetInterestingFiles()

	log.Debug("Parsing Info.plist")
	ar.ParsePlist()

	log.Debug("Analyzing MACHO executable")
	ar.MachoAnalyzer()

	log.Debug("Looking for path disclosures")
	ar.PathDiscover()

	log.Debug("Egg hunting inside the ipa bundle")
	ar.EggHunter()

	PrettyPrinter(&ar)

	log.Infof("Dumping data to files on '%s'", ar.ProjDir+"/analysisResult")
	FileDump(&ar)

	// log.Debug("Starting automated security risk analysis")
	// SecurityAnalysis(&ar)
}

// ===========
// = Helpers =
// ===========

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
