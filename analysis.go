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
	log "github.com/Sirupsen/logrus"
)

const (
	LC_ENCRYPTION_INFO_64 = 0x2c
	LC_ENCRYPTION_INFO    = 0x21
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
	MainOSVersion   string // iOS min version
	ExecutableFile  string // The executable binary (Mach-o or fatMach-o)

	// Processed data
	Plists              []string            // Plist files
	CertFiles           []string            // Certificate files
	ImpLibs             []string            // Imported libraries
	ImpSyms             []string            // Imported symbols
	SymTab              []string            // Symbols table
	Strings             []string            // Binary strings
	ATSec               map[string]bool     // NSAppTransportSecurity constrains
	AllowStackExecution bool                // Allows stack code execution
	RootSafe            bool                // Root safe execution flag
	SetuidSafe          bool                // SetuidSafe flag
	IsPIE               bool                // Compiled with PIE
	NoHeapExecution     bool                // Has NoHeapExecution flag
	DisclosedPaths      []string            // Disclosed paths
	URLs                []string            // Binary available strings
	WorthyEggs          map[string][]string // Saves file name and its interesting info
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
func (ar *AnalysisResult) MachoAnalyzer() {
	var err error
	var machoObject *macho.File

	// TODO: Parse Mach-O Fat binary
	// machoFat, errFat := macho.OpenFat(filepath.Join(
	// 	ar.ProjDir, "Payload", ar.AppContainer, ar.ExecutableFile,
	// ))
	// if errFat == nil {
	// 	m := machoFat.Arches[0]
	// 	machoObject = m.
	// }

	machoSlim, errSlim := macho.Open(filepath.Join(
		ar.ProjDir, "Payload", ar.AppContainer, ar.ExecutableFile,
	))
	if errSlim == nil {
		machoObject = machoSlim
	}

	defer machoSlim.Close()

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
		NSAppTransportSecurity map[string]bool `plist:"NSAppTransportSecurity"`
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
	ar.MainOSVersion = v.MinimumOSVersion
	ar.ATSec = v.NSAppTransportSecurity

	// pp.Println(v)
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

	urlRegex := regexp.MustCompile(`(http|ftp|https):\/\/[\w-]+(\.[\w-]+)+([\w.,@?^=%&amp;:\/~+#-]*[\w@?^=%&amp;\/~+#-])?`)
	ipAddrRegex := regexp.MustCompile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	googleAPIRegex := regexp.MustCompile(`\W(AIza.{35})`)
	// emailRegexp := regexp.MustCompile(`[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}`)
	emailRegexp := regexp.MustCompile(`[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})`)
	awsRegexp := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	gitHubRegexp := regexp.MustCompile(`[g|G][i|I][t|T][h|H][u|U][b|B].*[['|\"]0-9a-zA-Z]{35,40}['|\"]`)
	googleOAuthRegexp := regexp.MustCompile(`(\"client_secret\":\"[a-zA-Z0-9-_]{24}\")`)
	twitterOAuthRegexp := regexp.MustCompile(`[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]`)
	facebookOAuthRegexp := regexp.MustCompile(`[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]`)
	slackOAuthRegexp := regexp.MustCompile(`(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`)
	herokuRegexp := regexp.MustCompile(`[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`)
	genericRegexp := regexp.MustCompile(`[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]`)

	// Extract URLs
	for _, line := range ar.Strings {
		if urlRegex.Match([]byte(line)) {
			ar.URLs = append(ar.URLs, line)
			// log.Println(line)
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

		if googleAPIRegex.Match(buff) {
			ar.WorthyEggs["GoogleAPI"] = append(ar.WorthyEggs["GoogleAPI"], file)
		} else if ipAddrRegex.Match(buff) {
			ar.WorthyEggs["IPAddress"] = append(ar.WorthyEggs["IPAddress"], file)
		} else if emailRegexp.Match(buff) {
			ar.WorthyEggs["EmailAddress"] = append(ar.WorthyEggs["EmailAddress"], file)
		} else if awsRegexp.Match(buff) {
			ar.WorthyEggs["AWS"] = append(ar.WorthyEggs["AWS"], file)
		} else if gitHubRegexp.Match(buff) {
			ar.WorthyEggs["GitHub"] = append(ar.WorthyEggs["GitHub"], file)
		} else if googleOAuthRegexp.Match(buff) {
			ar.WorthyEggs["GoogleOAuth"] = append(ar.WorthyEggs["GoogleOAuth"], file)
		} else if twitterOAuthRegexp.Match(buff) {
			ar.WorthyEggs["TwitterOAuth"] = append(ar.WorthyEggs["TwitterOAuth"], file)
		} else if facebookOAuthRegexp.Match(buff) {
			ar.WorthyEggs["FacebookOAuth"] = append(ar.WorthyEggs["FacebookOAuth"], file)
		} else if slackOAuthRegexp.Match(buff) {
			ar.WorthyEggs["SlackOAuth"] = append(ar.WorthyEggs["SlackOAuth"], file)
		} else if herokuRegexp.Match(buff) {
			ar.WorthyEggs["HerokuOAuth"] = append(ar.WorthyEggs["HerokuOAuth"], file)
		} else if genericRegexp.Match(buff) {
			ar.WorthyEggs["GenericToken"] = append(ar.WorthyEggs["GenericToken"], file)
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
