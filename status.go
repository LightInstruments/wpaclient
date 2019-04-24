package wpaclient

type Status struct {
	WpaState string
	Address string
	UUID string
	BSSID string
	Freq uint
	SSID string
	Id uint
	Mode string
	PairwiseCipher string
	GroupCipher string
	KeyMgmt string
}
