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
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	plist "github.com/DHowett/go-plist"
	// log "github.com/sirupsen/logrus"
)

const (
	// LC_ENCRYPTION_INFO_64 encrypted ARM64 ipa flag
	LC_ENCRYPTION_INFO_64 = 0x2c
	// LC_ENCRYPTION_INFO encrypted ARM ipa flag
	LC_ENCRYPTION_INFO = 0x21
)

// AnalysisResult holds all the information relative to the analysis
type AnalysisResult struct {
	// Project metadata
	ProjDir       string   // Project directory
	FileName      string   // IPA file name
	AppFiles      []string // Name of all files in the ipa bundle
	NumberOfFiles int      // Number of files inside the IPA bundle
	AppContainer  string   // The name of the application container foo.app

	// IPA metadata
	AppName         string // Application name
	FileSize        int64  // IPA size
	MD5             string // IPA md5
	SHA1            string // IPA sha1
	SHA256          string // IPA sha256
	BundleName      string // Application bundle name
	SDKName         string // iOS SDK name
	Version         string // Application version
	PlatformVersion string // iOS version
	MinOSVersion    string // iOS min version
	ExecutableFile  string // The executable binary (Mach-o or fatMach-o)

	// Processed data
	Plists              []string            // Plist files
	CertFiles           []string            // Certificate files
	ImpLibs             []string            // Imported libraries
	ImpSyms             []string            // Imported symbols
	SymTab              []string            // Symbols table
	Strings             []string            // Binary strings
	ATSec               interface{}         // NSAppTransportSecurity constrains
	AllowStackExecution bool                // Allows stack code execution
	RootSafe            bool                // Root safe execution flag
	SetuidSafe          bool                // SetuidSafe flag
	IsPIE               bool                // Compiled with PIE
	NoHeapExecution     bool                // Has NoHeapExecution flag
	DisclosedPaths      []string            // Disclosed paths
	URLs                []string            // Binary available strings
	WorthyEggs          map[string][]string // Saves file name and its interesting info
	Tokens              map[string][]string // Saves the tokens
}

var eggs = map[string]*regexp.Regexp{
	// Generic usefull data
	"URL":           regexp.MustCompile(`(http|ftp|https):\/\/[\w-]+(\.[\w-]+)+([\w.,@?^=%&amp;:\/~+#-]*[\w@?^=%&amp;\/~+#-])?`),
	"EmailAddress":  regexp.MustCompile(`[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})`),
	"IPAddress":     regexp.MustCompile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`),
	"GoogleAPI":     regexp.MustCompile(`\W(AIza.{35})`),
	"GitHub":        regexp.MustCompile(`[g|G][i|I][t|T][h|H][u|U][b|B].*[['|\"]0-9a-zA-Z]{35,40}['|\"]`),
	"GoogleOAuth":   regexp.MustCompile(`(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")`),
	"TwitterOAuth":  regexp.MustCompile(`[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]`),
	"FacebookOAuth": regexp.MustCompile(`[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]`),
	"SlackOAuth":    regexp.MustCompile(`(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`),
	"HerokuOAuth":   regexp.MustCompile(`[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
	"GenericToken":  regexp.MustCompile(`[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]`),
	// AWS Keys
	"AWSAccessToken": regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
	// "AWSContentCredentials": regexp.MustCompile(`(?i)ACCA[0-9A-Z]{16}`),
	// "AWSGroup":              regexp.MustCompile(`(?i)AGPA[0-9A-Z]{16}`),
	// "AWSIAMUser":            regexp.MustCompile(`(?i)AIDA[0-9A-Z]{16}`),
	// "AWSEC2Instance":        regexp.MustCompile(`(?i)AIPA[0-9A-Z]{16}`),
	// "AWSManagedPolicy":      regexp.MustCompile(`(?i)ANVA[0-9A-Z]{16}`),
	// "AWSPublicKey":          regexp.MustCompile(`(?i)APKA[0-9A-Z]{16}`),
	// "AWSRole":               regexp.MustCompile(`(?i)AROA[0-9A-Z]{16}`),
	// "AWSCertficate":         regexp.MustCompile(`(?i)ASCA[0-9A-Z]{16}`),
	// "AWSTemporary":          regexp.MustCompile(`(?i)ASIA[0-9A-Z]{16}`),
}

// HashCalculator retuns the file information
func (ar *AnalysisResult) HashCalculator(ipaFile string) {
	fileBuf, err := ioutil.ReadFile(ipaFlag)
	checkError(err)

	md5sum := md5.Sum(fileBuf)
	sha1sum := sha1.Sum(fileBuf)
	sha256sum := sha256.Sum256(fileBuf)

	ar.MD5 = hex.EncodeToString(md5sum[:])
	ar.SHA1 = hex.EncodeToString(sha1sum[:])
	ar.SHA256 = hex.EncodeToString(sha256sum[:])
}

// MachoAnalyzer retuns the file information
// https://github.com/aidansteele/osx-abi-macho-file-format-reference
// https://github.com/hackrose/macho-go
// https://mandalorian.com/2013/05/03/decrypting-ios-binaries/
// TODO: Parse Mach-O Fat binary
// TODO: Check if binary is encrypted
func (ar *AnalysisResult) MachoAnalyzer() {
	var err error
	// var machoObject *macho.File

	// TODO: Parse Mach-O Fat binary
	// machoFat, errFat := macho.OpenFat(filepath.Join(
	// 	ar.ProjDir, "Payload", ar.AppContainer, ar.ExecutableFile,
	// ))
	// if errFat == nil {
	// 	m := machoFat.Arches[0]
	// 	machoObject = m.
	// }

	machoSlim, err := macho.Open(filepath.Join(
		ar.ProjDir, "Payload", ar.AppContainer, ar.ExecutableFile,
	))
	if err == nil {
		defer machoSlim.Close()

		machoObject := machoSlim

		ar.ImpLibs, err = machoObject.ImportedLibraries()
		checkError(err)

		ar.ImpSyms, err = machoObject.ImportedSymbols()
		checkError(err)

		// // TODO: Check if binary is encrypted
		// pp.Println(machoObject.Symtab.Cmd)
		// pp.Println(machoObject.Symtab.Cmd&LC_ENCRYPTION_INFO_64 == LC_ENCRYPTION_INFO_64)
		// pp.Println(machoObject.Symtab.Cmd&LC_ENCRYPTION_INFO == LC_ENCRYPTION_INFO)

		for _, section := range machoObject.Sections {
			if section.Name == "__cstring" { //|| section.Name == "__data" {
				str, err := section.Data()
				if err != nil {
					log.Error("No available strings in '__cstring' section: %s", err.Error())
				}

				bArr := bytes.Split(str, []byte{0x00})
				for _, line := range bArr {
					if len(line) > 1 {
						store := true

						for i := range line {
							if !isPrintable(line[i]) {
								store = false
							}
						}

						if store {
							strippedLine := strings.TrimSpace(string(line))
							ar.Strings = append(ar.Strings, strippedLine)
						}
					}
				}
			}
		}

		syms := machoObject.Symtab
		for _, s := range syms.Syms {
			ar.SymTab = append(ar.SymTab, s.Name)
		}

		ar.AllowStackExecution = machoObject.Flags&macho.FlagAllowStackExecution == macho.FlagAllowStackExecution
		ar.RootSafe = machoObject.Flags&macho.FlagRootSafe == macho.FlagRootSafe
		ar.SetuidSafe = machoObject.Flags&macho.FlagSetuidSafe == macho.FlagSetuidSafe
		ar.IsPIE = machoObject.Flags&macho.FlagPIE == macho.FlagPIE
		ar.NoHeapExecution = machoObject.Flags&macho.FlagNoHeapExecution == macho.FlagNoHeapExecution

		return
	}

	machoFat, err := macho.OpenFat(filepath.Join(
		ar.ProjDir, "Payload", ar.AppContainer, ar.ExecutableFile,
	))
	if err == nil {
		defer machoFat.Close()
		fatArches := machoFat.Arches
		// for _, arch := range fatArches {
		// 	log.Println(arch.Cpu.String())
		// }
		machoFObject := fatArches[0]

		ar.ImpLibs, err = machoFObject.ImportedLibraries()
		checkError(err)

		ar.ImpSyms, err = machoFObject.ImportedSymbols()
		checkError(err)

		// // TODO: Check if binary is encrypted
		// pp.Println(machoFObject.Symtab.Cmd)
		// pp.Println(machoFObject.Symtab.Cmd&LC_ENCRYPTION_INFO_64 == LC_ENCRYPTION_INFO_64)
		// pp.Println(machoFObject.Symtab.Cmd&LC_ENCRYPTION_INFO == LC_ENCRYPTION_INFO)

		for _, section := range machoFObject.Sections {
			if section.Name == "__cstring" { //|| section.Name == "__data" {
				str, err := section.Data()
				if err != nil {
					log.Error("No available strings in '__cstring' section: %s", err.Error())
				}

				bArr := bytes.Split(str, []byte{0x00})
				for _, line := range bArr {
					if len(line) > 1 {
						store := true

						for i := range line {
							if !isPrintable(line[i]) {
								store = false
							}
						}

						if store {
							strippedLine := strings.TrimSpace(string(line))
							ar.Strings = append(ar.Strings, strippedLine)
						}
					}
				}
			}
		}

		syms := machoFObject.Symtab
		for _, s := range syms.Syms {
			ar.SymTab = append(ar.SymTab, s.Name)
		}

		ar.AllowStackExecution = machoFObject.Flags&macho.FlagAllowStackExecution == macho.FlagAllowStackExecution
		ar.RootSafe = machoFObject.Flags&macho.FlagRootSafe == macho.FlagRootSafe
		ar.SetuidSafe = machoFObject.Flags&macho.FlagSetuidSafe == macho.FlagSetuidSafe
		ar.IsPIE = machoFObject.Flags&macho.FlagPIE == macho.FlagPIE
		ar.NoHeapExecution = machoFObject.Flags&macho.FlagNoHeapExecution == macho.FlagNoHeapExecution
	}
}

// GetInterestingFiles populates the struct with important files
func (ar *AnalysisResult) GetInterestingFiles() {
	for _, file := range ar.AppFiles {
		if strings.Contains(file, ".plist") ||
			strings.Contains(file, ".mobileprovision") {
			ar.Plists = append(ar.Plists, file)
		} else if strings.Contains(file, ".cer") ||
			strings.Contains(file, ".der") ||
			strings.Contains(file, ".pem") ||
			strings.Contains(file, ".p12") ||
			strings.Contains(file, ".pfx") {
			ar.CertFiles = append(ar.CertFiles, file)
		}
	}
}

// ParsePlist extracts the ipa Info.plist file and extracts useful information
func (ar *AnalysisResult) ParsePlist() {
	re := regexp.MustCompile(`(?i)Payload/[a-z0-9].*\.app/Info\.plist`)

	var infPlist string
	for _, file := range ar.Plists {
		if re.MatchString(file) {
			infPlist = file
			break
		}
	}

	if infPlist == "" {
		log.Fatal("Main Info.plist not found")
	}

	var v struct {
		CFBundleExecutable  string `plist:"CFBundleExecutable"`
		CFBundleDisplayName string `plist:"CFBundleDisplayName"`
		CFBundleIdentifier  string `plist:"CFBundleIdentifier"`
		DTSDKName           string `plist:"DTSDKName"`
		CFBundleVersion     string `plist:"CFBundleVersion"`
		DTPlatformVersion   string `plist:"DTPlatformVersion"`
		MinimumOSVersion    string `plist:"MinimumOSVersion"`
		// App Transport Security (ATS) is disabled on the domain
		// '{'NSAllowsArbitraryLoads': True}'. Disabling ATS can allow insecure
		// communication with particular servers or allow insecure loads for web
		// views or for media, while maintaining ATS protections elsewhere in
		// your app.
		NSAppTransportSecurity interface{} `plist:"NSAppTransportSecurity"`
	}

	infPlistBuf, err := ioutil.ReadFile(filepath.Join(ar.ProjDir, infPlist))
	checkError(err)
	_, err = plist.Unmarshal(infPlistBuf, &v)
	checkError(err)

	ar.ExecutableFile = v.CFBundleExecutable
	ar.AppName = v.CFBundleDisplayName
	ar.BundleName = v.CFBundleIdentifier
	ar.SDKName = v.DTSDKName
	ar.Version = v.CFBundleVersion
	ar.PlatformVersion = v.DTPlatformVersion
	ar.MinOSVersion = v.MinimumOSVersion
	ar.ATSec = v.NSAppTransportSecurity
}

// PathDiscover finds path disclosures
// TODO: Search inside nib files
func (ar *AnalysisResult) PathDiscover() {
	pathRegex := regexp.MustCompile(`^\/[\w./]*$`)

	for _, line := range ar.Strings {
		if pathRegex.Match([]byte(line)) {
			ar.DisclosedPaths = append(ar.DisclosedPaths, line)
		}
	}
}

// EggHunter searches for tokens, urls, usernames, passwords…
// TODO: Search inside nib files
func (ar *AnalysisResult) EggHunter() {
	ar.WorthyEggs = map[string][]string{}
	ar.Tokens = map[string][]string{}

	// Extract URLs
	for _, line := range ar.Strings {
		if eggs["URL"].Match([]byte(line)) {
			ar.URLs = append(ar.URLs, line)
		}
	}

	// Look for files containing interesting stuff
	for _, file := range ar.AppFiles {
		fPath := filepath.Join(ar.ProjDir, file)
		if fi, _ := os.Stat(fPath); fi.IsDir() {
			continue
		}

		buff, err := ioutil.ReadFile(fPath)
		if err != nil {
			log.Error(err)
		}

		for name, re := range eggs {
			if re.Match(buff) {
				match := re.FindStringSubmatch(string(buff))
				// if name != "URL" && name != "EmailAddress" {
				if name == "GoogleAPI" || name == "AWSAccessToken" {
					// pp.Println(match[0])
					ar.Tokens[name] = append(ar.Tokens[name], match[0])
				}

				ar.WorthyEggs[name] = append(ar.WorthyEggs[name], file)
			}
		}
	}
}

// ===========
// = Helpers =
// ===========

func isPrintable(b byte) bool {
	if b < 32 || b > 126 {
		return false
	}
	return true
}
