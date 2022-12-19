package lib

import (
	"bytes"
	"compress/flate"
	"fmt"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows/registry"
	"io"
	"io/ioutil"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"golang.org/x/text/transform"
	"golang.org/x/net/html/charset"
	"unicode"
)

func transformString(t transform.Transformer, s string) (string, error) {
	r := transform.NewReader(strings.NewReader(s), t)
	b, err := ioutil.ReadAll(r)
	return string(b), err
}
func Decode(otherEncodeStr, encodeType string) (string, error) {
	e, _ := charset.Lookup(encodeType)
	if e == nil {
		return "", fmt.Errorf("%s: not found", encodeType)
	}
	decodeStr, err := transformString(e.NewDecoder(), otherEncodeStr)
	if err != nil {
		return "", err
	}
	return decodeStr, nil
}

func GetMDEProcessEx() (bool, []string){
	var pname []string
	var flag bool
	pids,_ := process.Pids()
	for _, pid := range pids {
		pn,_ := process.NewProcess(pid)
		pName,_ :=pn.Name()
		if strings.Contains(pName, "xagt") || strings.Contains(pName, "MsSense") || strings.Contains(pName, "MsMPEng") || strings.Contains(pName, "SenseCE"){
			pname = append(pname,pName)
		}
	}
	if len(pname) == 3{
		flag = true
	} else{
		flag = false
	}
	return flag, pname
}


func GetDsRegStatus() map[string]string{
	result := map[string]string{}
	cmd := exec.Command("dsregcmd.exe", "/status")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	resultStr := out.String()
	for _, k := range strings.Split(resultStr, "\n"){
		//fmt.Println(k)
		complieFlag, _:= regexp.MatchString(" *[A-z]+ : [A-z0-9\\{\\}]+ *", k)
		if complieFlag{
			name := strings.TrimSpace(strings.Split(k, ":")[0])
			value := strings.TrimSpace(strings.Split(k, ":")[1])
			//fmt.Println(name)
			//fmt.Println(value)
			result[name] = value
		}
	}

	return result
}



func GetSettingsFromRegistry(regKey string, subitem string) (string, error) {
	result := ""
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regKey, registry.QUERY_VALUE)
	if err != nil {

		return result, err
	}
	defer k.Close()

	result , err = getRegistryValueAsString(k, subitem)
	return result, err
}

func GetRegistryValueAsBinaryDecode(regKey string, subKey string) (string, error){
	var result []byte
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regKey, registry.QUERY_VALUE)
	if err != nil {

		return "", err
	}
	result, _,  err = k.GetBinaryValue(subKey)
	if err != nil {

		return "", err
	}
	bReader := bytes.NewReader(result)
	var out bytes.Buffer
	flateReader := flate.NewReader(bReader)
	defer flateReader.Close()
	io.Copy(&out, flateReader)

	tmpByte := out.Bytes()
	//newByte := bytes.ReplaceAll(tmpByte, []byte{0}, []byte{32})
	newByte := bytes.Trim(tmpByte, "\x00\x00")
	newByte = bytes.Trim(tmpByte, "\x00")
	newResult := string(newByte)
	newResult = TrimZero(newResult)
	// unicode 解码
	//decoder := charmap.Windows1250.NewDecoder()
	//reader := decoder.Reader(strings.NewReader(out.String()))
	//b, _ := ioutil.ReadAll(reader)
	//
	//fmt.Println("Decoded: " + string(b))
	//
	//tmp := width.Narrow.String(string(b))
	return newResult, err
}
func TrimZero(s string) string {
	str := make([]rune, 0, len(s))
	for _, v := range []rune(s) {
		if !unicode.IsLetter(v) && !unicode.IsDigit(v) && !unicode.IsPrint(v) {
			continue
		}

		str = append(str, v)
	}
	return string(str)
}
func getRegistryValueAsString(key registry.Key, subKey string) (string, error) {
	var valByte []byte
	valString, _, err := key.GetStringValue(subKey)
	if err == nil {
		return valString, nil
	}
	valStrings, _, err := key.GetStringsValue(subKey)
	if err == nil {
		return strings.Join(valStrings, "\n"), nil
	}
	valBinary, _, err := key.GetBinaryValue(subKey)
	if err == nil {
		return string(valBinary), nil
	}
	valInteger, _, err := key.GetIntegerValue(subKey)
	if err == nil {
		return strconv.FormatUint(valInteger, 10), nil
	}
	key.GetValue(subKey,valByte)
	if err == nil {
		return string(valByte),nil
	}

	return "", err
}

func GetServiceStatus(name string) bool{
	var out bytes.Buffer
	cmd := exec.Command("sc.exe", "query", name)
	cmd.Stdout = &out
	cmd.Run()
	cmd.Wait()
	if strings.Contains(out.String(), "RUNNING"){
		return true
	} else{
		return false
	}
}