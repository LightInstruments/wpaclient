package wpaclient

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// AuthReq represents data received with "CTRL-REQ-" requests
type AuthReq struct {
	ID   int
	Type string
	Text string
}

// Event represends events received from wpa_supplicant
type Event struct {
	Sev     int
	Message string
	AuthReq *AuthReq
	Err     error
	FullMessage string
	Args    map[string]string
}

func parseEvent(b []byte) *Event {
	if len(b) < 5 {
		msg := strings.TrimSuffix(string(b), "\n")
		return &Event{Err: errors.Errorf("message too short (%s)", msg)}
	}

	sb, err := strconv.Atoi(string(b[1]))
	if err != nil {
		return &Event{Err: errors.Wrap(err, "parse severity")}
	}

	fullmsg := strings.TrimSuffix(string(b[3:]), "\n")
	re := regexp.MustCompile("CTRL-[A-Z-]+[ ]")
	msg := re.FindString(fullmsg)
	argsString := fullmsg[len(msg):]
	argsArray := strings.Split(argsString, " ")
	argsMap := make(map[string]string)
	for _, element := range argsArray {
		elementSplitted := strings.Split(element, "=")
		if len(elementSplitted) != 2 {
			continue
		}
		key := elementSplitted[0]
		value := elementSplitted[1]
		if key == "ssid" && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1:len(value)-1]
		}
		argsMap[key] = value
	}

	if strings.HasPrefix(msg, WpaCtrlReq) {
	msg = strings.TrimPrefix(msg, WpaCtrlReq)

		i := strings.Index(msg, "-")
		j := strings.Index(msg, ":")

		id, err := strconv.Atoi(msg[i+1 : j])
		if err != nil {
			return &Event{Err: errors.Wrap(err, "parse networkID")}
		}

		return &Event{Sev: sb, Message: WpaCtrlReq,
			AuthReq: &AuthReq{ID: id, Type: msg[:i], Text: msg[j+1:]}, Args: argsMap, FullMessage: fullmsg}
	}

	return &Event{Sev: sb, Message: msg, FullMessage: fullmsg, Args: argsMap}
}
