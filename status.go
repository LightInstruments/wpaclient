package wpaclient

import (
	"bytes"
	"encoding/csv"
	"net"
	"strconv"
	"strings"
)

type Status struct {
	WpaState string
	Address string
	UUID string
	BSSID net.HardwareAddr
	Freq uint
	SSID string
	Id uint
	Mode string
	PairwiseCipher string
	GroupCipher string
	KeyMgmt string
}

func parseStatus(data []byte) (*Status, error) {
	r := csv.NewReader(bytes.NewReader(data))

	recs, err := r.ReadAll()

	if err != nil {
		return nil, err
	}

	status := &Status{}

	for _, rec := range recs {
		for _, r := range rec {
			decomposed := strings.Split(r, "=")
				switch decomposed[0] {
					case "bssid":
						status.BSSID, err = net.ParseMAC(decomposed[1])
						if err != nil {
							continue
						}
				case "freq":
						i, err := strconv.Atoi(decomposed[1])
						if err != nil {
							continue
						}
						status.Freq = uint(i)
				case "ssid":
					status.SSID = decomposed[1]
				case "id":
					i, err := strconv.Atoi(decomposed[1])
					if err != nil {
						continue
					}
					status.Id = uint(i)
				case "mode":
					status.Mode = decomposed[1]
				case "pairwise_cipher":
					status.PairwiseCipher = decomposed[1]
				case "group_cipher":
					status.GroupCipher = decomposed[1]
				case "key_mgmt":
					status.KeyMgmt = decomposed[1]
				case "wpa_state":
					status.WpaState = decomposed[1]
				case "address":
					status.Address = decomposed[1]
				case "uuid":
					status.UUID = decomposed[1]
				}
			}
		}
	return status, nil
}

func (self *Status) IsConnected() bool {
	return self.WpaState == "COMPLETED"
}