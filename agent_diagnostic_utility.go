package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"./log"

	"github.com/appveen/go-log/logger"
	vault "github.com/appveen/govault"
	"github.com/howeyc/gopass"
)

var Logger logger.Logger

var confFilePath = flag.String("c", "./conf/agent.conf", "Conf File Path")
var password = flag.String("p", "", "Vault Password")
var ODPCertFile []byte
var ODPKeyFile []byte
var TrustCerts []string
var confData map[string]string
var baseUrl string

type temp interface{}

func main() {
	flag.Parse()

	if string(*password) == "" {
		fmt.Print("Enter Password : ")
		passBytes, err := gopass.GetPasswdMasked()
		if err != nil {
			fmt.Print("Error - ", err.Error())
		}
		pwd := string(passBytes)
		password = &pwd
	}

	confData = readCentralConfFile(*confFilePath)

	var wg sync.WaitGroup

	logClient := FetchHTTPClient()
	logsHookURL := baseUrl + "/logs"
	headers := map[string]string{}
	Loggerservice := log.Logger{}
	Logger = Loggerservice.GetLogger("DiagnosticUtility", "Info", "DiagnosticAgent", "AGENT1000", "10", "104857600", "SIZE", logsHookURL, logClient, headers)

	_, agentType := determineAgentType(*password)
	Logger.Info("Successfuly Logged in to vault")
	Logger.Info("Agent Type - %s", agentType)

	var directoryPaths []string
	directoryPath, err := filepath.Abs(filepath.Dir(os.Args[0]))
	directoryPaths = append(directoryPaths, directoryPath)
	directoryPaths = append(directoryPaths, strings.Replace(directoryPath, "bin", "conf", -1))
	directoryPaths = append(directoryPaths, strings.Replace(directoryPath, "bin", "data", -1))
	directoryPaths = append(directoryPaths, strings.Replace(directoryPath, "bin", "log", -1))

	for _, dirPath := range directoryPaths {
		Logger.Info("Testing file creation, updation and deletion on directory - " + dirPath)
		if err != nil {
			Logger.Error("Error fetching directory -: " + err.Error())
		}

		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			Logger.Error("Directory "+dirPath+" Doesn't Exist, Error - ", err.Error())
		} else {
			Logger.Info("Creating dummy file in " + dirPath)
			file, err := os.Create(dirPath + string(os.PathSeparator) + "Dummy.txt")
			if err != nil {
				Logger.Error("File creation error - ", err)
			}

			// time.Sleep((2) * time.Second)
			Logger.Info("Writing to dummy file in " + dirPath)
			_, err = file.WriteString("Creating and writing to file is successfull")
			if err != nil {
				Logger.Error("Writing to file error - ", err)
			}

			file.Close()
			// time.Sleep((2) * time.Second)
			Logger.Info("Deleting the dummy file in " + dirPath)
			err = os.Remove(dirPath + string(os.PathSeparator) + "Dummy.txt")
			if err != nil {
				Logger.Error("File deletion error - ", err.Error())
			}
		}
	}

	initCentralHeartBeat(&wg)
	wg.Wait()
}

func determineAgentType(password string) (string, string) {
	d, _, _ := getExecutablePathAndName()
	Vault, err := vault.InitVault(filepath.Join(d, "..", "conf", "db.vault"), password)
	if err != nil {
		fmt.Print("Incorrect vault password")
		os.Exit(1)
	}

	agentTypeByte, err := Vault.Get("agent-type")
	if err != nil {
		Logger.Error("Error fetching data from vault - ", err.Error())
		Vault.Close()
		os.Exit(1)
	}

	key, err := Vault.Get("odp.key")
	if err != nil {
		Logger.Error("%s", err)
	}
	keyString := string(key)
	ODPKeyFile, err = base64.StdEncoding.DecodeString(keyString)
	if err != nil {
		Logger.Error("%s", err)
	}

	cert, err := Vault.Get("odp.cert")
	if err != nil {
		Logger.Error("%s", err)
	}
	certString := string(cert)
	ODPCertFile, err = base64.StdEncoding.DecodeString(certString)
	if err != nil {
		Logger.Error("%s", err)
	}

	caCertString, err := Vault.Get("trustCerts")
	if err != nil {
		Logger.Error("%s", err)
	}
	var trustStore []string
	if len(caCertString) > 0 {
		err := json.Unmarshal(caCertString, &trustStore)
		if err != nil {
			Logger.Error("Error in fetching trust store for agent")
			os.Exit(0)
		}
	}
	TrustCerts = trustStore
	TrustCerts = append(TrustCerts, certString)

	baseURL, err := Vault.Get("base-url")
	if err != nil {
		Logger.Error("%s", err)
	}
	baseUrl = "https://" + string(baseURL)

	Vault.Close()
	return string(password), string(agentTypeByte)

}

func getExecutablePathAndName() (string, string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	d, f := filepath.Split(executablePath)
	return d, f, nil
}

func initCentralHeartBeat(wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	var client = FetchHTTPClient()
	frequency, err := strconv.Atoi(confData["heartbeat-frequency"])
	if err != nil {
		Logger.Error("Error %s", err)
	}
	Logger.Info("Hearbeat Frequency - ", frequency)

	pings, err := strconv.Atoi(confData["no-of-pings"])
	if err != nil {
		Logger.Error("Error %s", err)
	}

	for i := 0; i < pings; i++ {
		var request temp
		var response temp
		headers := make(map[string]string)
		headers["AgentID"] = "AGENT1000"
		headers["AgentName"] = "DummyAgent"
		headers["NodeHeartBeatFrequency"] = confData["heartbeat-frequency"]
		Logger.Info("Heartbeat Headers %v", headers)
		Logger.Info("Making Request to B2BGW at -: %s", baseUrl+"/heartbeat")
		err := makeJSONRequest(client, baseUrl+"/heartbeat", request, headers, &response)
		if err != nil {
			Logger.Error("Heartbeat Error %s", err.Error())
			time.Sleep(time.Duration(frequency) * time.Second)
			continue
		}
		Logger.Info("Response from B2BGW - %s", response)
		time.Sleep(time.Duration(frequency) * time.Second)
	}
}

func FetchHTTPClient() *http.Client {
	var client *http.Client
	if len(ODPCertFile) != 0 && len(ODPKeyFile) != 0 {
		client = getNewHTTPClient(prepareTLSTransportConfigWithEncodedTrustStore(ODPCertFile, ODPKeyFile, TrustCerts))
	} else {
		client = getNewHTTPClient(nil)
	}
	return client
}

func getNewHTTPClient(transport *http.Transport) *http.Client {
	if transport != nil {
		return &http.Client{Transport: transport}
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

func prepareTLSTransportConfigWithEncodedTrustStore(certFile []byte, keyFile []byte, trustCerts []string) *http.Transport {
	cert, err := tls.X509KeyPair(certFile, keyFile)
	if err != nil {
		Logger.Error("Error 1 %s", err)
	}
	caCertPool := x509.NewCertPool()
	for i := 0; i < len(trustCerts); i++ {
		currentEncodedCert := trustCerts[i]
		decodedCert, err := base64.StdEncoding.DecodeString(currentEncodedCert)
		if err != nil {
			Logger.Error("Error 2 %s", err)
		}
		caCertPool.AppendCertsFromPEM(decodedCert)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return transport
}

func readCentralConfFile(filePath string) map[string]string {
	data, err := readLinesToFile(filePath)
	if err != nil {
		Logger.Error("Read Line Error %s", err)
	}
	mappedValues := make(map[string]string)
	for _, item := range data {
		values := strings.Split(item, "=")
		if len(values) == 2 {
			mappedValues[values[0]] = values[1]
		} else {
			mappedValues[values[0]] = ""
		}
	}
	return mappedValues
}

func readLinesToFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func makeJSONRequest(client *http.Client, url string, payload interface{}, headers map[string]string, response interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, er := http.NewRequest("POST", url, bytes.NewReader(data))
	if er != nil {
		data = nil
		return er
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Close = true
	res, errr := client.Do(req)
	if errr != nil {
		data = nil
		return errr
	}
	if res.StatusCode != 200 {
		if res.Body != nil {
			responseData, _ := ioutil.ReadAll(res.Body)
			return errors.New(string(responseData))
		} else {
			return errors.New("Request failed status code " + http.StatusText(res.StatusCode))
		}
	}
	bytesData, err := ioutil.ReadAll(res.Body)
	if res.Body != nil {
		res.Body.Close()
	}
	if err != nil {
		bytesData = nil
		data = nil
		return err
	}
	err = json.Unmarshal(bytesData, &response)
	if err != nil {
		bytesData = nil
		data = nil
		return err
	}
	bytesData = nil
	data = nil
	return nil
}
