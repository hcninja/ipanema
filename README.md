# ipanema

Ipanema is a tool for iOS ipa application security assessment.

## Installation

The easiest way is to download a precompiled binary for your architecture and operating system from the releases tab.

If you want to build it by yourself follow this steps:

* `go get dev.hackercat.ninja/hcninja/ipanema`
* `go install dev.hackercat.ninja/hcninja/ipanema`

If this doesn't work, go to the project folder and do a `go get -u` before `go install`.

## Usage

The usage is easy, `ipanema -ipa my.ipa`, the analysis will output some useful info to stdout, and after the analysis finishes you will find all the analysis data in the temporal path created by ipanema under the folder `analysisResult`. This folder will contain multiple txt files with the data specified in the filename, useful to grep for info, aside of this, the whole analysis will be dumped in an `analysis.json` file, try to use `jq` to filter and search through the info.

## TODO

* [x] Basic analysis engine
* [x] CLI interface
* [x] Analysis output
* [x] Analysis project json dump
* [x] Search for valuable information available in the ipa bundle
* [ ] Automated analysis with recommendations
* [ ] Banned function analysis with an "exploitability" index
* [ ] Web GUI
* [ ] API
* [ ] Sandbox to do a dynamic analysis
* [ ] Function, methods and API fuzzing