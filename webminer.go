package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode"
)

type Amount uint64

func (amt Amount) MarshalJSON() ([]byte, error) {
	integer := uint64(amt) / 1_000_000_00
	decimal := uint64(amt) % 1_000_000_00
	decimalString := strconv.FormatUint(decimal, 10)
	if decimalString != "0" {
		// Pad with leading zeros
		for i := len(decimalString); i < 8; i++ {
			decimalString = "0" + decimalString
		}
		// Remove trailing zeros
		for decimalString[len(decimalString)-1] == '0' {
			decimalString = decimalString[:len(decimalString)-1]
		}
	}
	return []byte(fmt.Sprintf("\"%d.%s\"", integer, decimalString)), nil
}

func (amt *Amount) UnmarshalJSON(data []byte) error {
	var inner string
	if err := json.Unmarshal(data, &inner); err != nil {
		// Must not be wrapped as a string
		inner = string(data)
	}
	if strings.ContainsRune(inner, '.') {
		parts := strings.Split(inner, ".")
		if len(parts) != 2 {
			return fmt.Errorf("invalid amount: %v", data)
		}
		for _, rune := range parts[1] {
			if !unicode.IsDigit(rune) {
				return fmt.Errorf("invalid amount: %v", data)
			}
		}
		for i := len(parts[1]); i < 8; i++ {
			parts[1] += "0"
		}
		integer, err := strconv.ParseInt(parts[0], 10, 63)
		if err != nil {
			return err
		}
		decimal, err := strconv.ParseInt(parts[1], 10, 63)
		if err != nil {
			return err
		}
		*amt = Amount(integer*1_000_000_00 + decimal)
	} else {
		integer, err := strconv.ParseInt(inner, 10, 63)
		if err != nil {
			return err
		}
		*amt = Amount(integer * 1_000_000_00)
	}
	return nil
}

type ProtocolSettings struct {
	// The number of leading bits which must be zero for a work candidate to be
	// accepted by the server.
	Difficulty uint8 `json:"difficulty_target_bits"`
	// The ratio of initial issuance distributed to expected amount.
	Ratio float32 `json:"ratio"`
	// The amount the miner is allowed to claim.
	TotalReward Amount `json:"mining_amount"`
	// The amount which is surrendered to the server operator.
	ServerSubsidy Amount `json:"mining_subsidy_amount"`
	// The number of subsidy adjustment periods which have elapsed.
	Epoch uint16 `json:"epoch"`
}

func get_protocol_settings() (ProtocolSettings, error) {
	resp, err := http.Get("https://webcash.org/api/v1/target")
	if err != nil {
		return ProtocolSettings{}, err
	}
	defer resp.Body.Close()
	var settings ProtocolSettings
	err = json.NewDecoder(resp.Body).Decode(&settings)
	if err != nil {
		return ProtocolSettings{}, err
	}
	return settings, nil
}

func main() {
	settings, err := get_protocol_settings()
	if err != nil {
		panic(err)
	}
	fmt.Println(settings)
	data, err := json.Marshal(settings)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))
}
