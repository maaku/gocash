package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"math/bits"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unsafe"

	"golang.org/x/sync/errgroup"
)

/*
#cgo CFLAGS: -Ilibsha2/include
#cgo amd64 386 CFLAGS: -march=znver1
#include "libsha2/include/sha2/sha256.h"
#include "libsha2/lib/common.c"
#include "libsha2/lib/compat/byteswap.c"
#include "libsha2/lib/sha256.c"
// ARM
#include "libsha2/lib/sha256_armv8.c"
// Intel
#include "libsha2/lib/sha256_sse4.c"
#include "libsha2/lib/sha256_sse41.c"
#include "libsha2/lib/sha256_avx2.c"
#include "libsha2/lib/sha256_shani.c"

typedef struct sha256_ctx sha256_ctx_t;

void sha256_write_and_finalize8(struct sha256_ctx* ctx, const unsigned char nonce1[4], const unsigned char nonce2[4], const unsigned char final[4], const unsigned char hashes[8*32])
{
	unsigned char blocks[8*64] = { 0 };
	int i;
	for (i = 0; i < 8; ++i) {
		memcpy(blocks + i*64 + 0, nonce1, 4);
		memcpy(blocks + i*64 + 4, nonce2, 4);
		memcpy(blocks + i*64 + 8, final, 4);
		blocks[i*64 + 12] = 0x80; // padding byte
		WriteBE64(blocks + i*64 + 56, (ctx->bytes + 12) << 3);
		nonce2 += 4;
	}
	sha256_midstate((struct sha256*)hashes, ctx->s, blocks, 8);
}

void sha256_write_and_finalize_many(struct sha256_ctx* ctx, const unsigned char nonce1[4], const unsigned char nonce2[4], const unsigned char final[4], const unsigned char* hashes, unsigned int n)
{
	for (int k = 0; k < n; ++k) {
		sha256_write_and_finalize8(ctx, nonce1, &nonce2[4*k], final, &hashes[k*8*32]);
	}
}
*/
import "C"

func GetTermsOfService() (string, error) {
	const server = "http://127.0.0.1:8000"

	resp, err := http.Get(server + "/terms/text")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

type Uint256 [32]byte

func (hash Uint256) String() string {
	// encode as hex
	return fmt.Sprintf("0x%x", hash[:])
}

func ApparentDifficulty(hash Uint256) uint8 {
	diff := 0
	for i := 0; i < 32; i++ {
		c := hash[i]
		if c == 0 {
			diff += 8
			continue
		}
		diff += bits.LeadingZeros8(c)
		break
	}
	return uint8(diff)
}

func CheckProofOfWork(hash Uint256, difficulty uint8) bool {
	for i := 0; i < int(difficulty/8); i++ {
		if hash[i] != 0 {
			return false
		}
	}
	if difficulty%8 != 0 {
		if hash[difficulty/8]>>(8-difficulty%8) != 0 {
			return false
		}
	}
	return true
}

type Amount uint64

func (amt Amount) String() string {
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
		return fmt.Sprintf("%d.%s", integer, decimalString)
	}
	return fmt.Sprintf("%d", integer)
}

func (amt Amount) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", fmt.Sprint(amt)[1:])), nil
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

type SecretWebcash struct {
	// The actual secret, typically a 64-character hex string but in principle
	// any Unicode string value.
	Secret string `json:"secret"`
	// The amount of Webcash held by the secret.
	Amount Amount `json:"amount"`
}

func (sk SecretWebcash) String() string {
	return fmt.Sprintf("e%v:secret:%s", sk.Amount, sk.Secret)
}

func (sk SecretWebcash) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", sk.String())), nil
}

type PublicWebcash struct {
	// The public hash, a 32-byte SHA-256 hash of the secret string.
	Hash Uint256 `json:"hash"`
	// The amount of Webcash held by the secret.
	Amount Amount `json:"amount"`
}

func (pk PublicWebcash) String() string {
	return fmt.Sprintf("e%v:public:%v", pk.Amount, pk)
}

func (sk PublicWebcash) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", sk.String())), nil
}

// FromSecret converts a SecretWebcash to a PublicWebcash.
func FromSecret(sk SecretWebcash) PublicWebcash {
	return PublicWebcash{
		Hash:   sha256.Sum256([]byte(sk.Secret)),
		Amount: sk.Amount,
	}
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
	const server = "http://127.0.0.1:8000"

	resp, err := http.Get(server + "/api/v1/target")
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

func get_speed_string(attempts uint64, elapsed time.Duration) string {
	if elapsed == 0 {
		return "0.00 H/s"
	}
	speed := float64(attempts) / elapsed.Seconds()
	if speed < 1_000 {
		return fmt.Sprintf("%.2f H/s", speed)
	}
	if speed < 1_000_000 {
		return fmt.Sprintf("%.2f KH/s", speed/1_000)
	}
	if speed < 1_000_000_000 {
		return fmt.Sprintf("%.2f MH/s", speed/1_000_000)
	}
	if speed < 1_000_000_000_000 {
		return fmt.Sprintf("%.2f GH/s", speed/1_000_000_000)
	}
	return fmt.Sprintf("%.2f TH/s", speed/1_000_000_000_000)
}

func get_expect_string(attempts uint64, elapsed time.Duration, difficulty uint8) string {
	if elapsed == 0 {
		return "unknown"
	}
	speed := float64(attempts) / elapsed.Seconds()
	expect := math.Round(math.Exp2(float64(difficulty)) / speed)
	if expect >= math.Exp2(64) {
		return "never"
	}
	sec := uint64(expect)
	min := sec / 60
	hr := min / 60
	day := hr / 24
	var res string
	if day > 0 {
		res += fmt.Sprintf("%dd ", day)
	}
	if hr > 0 {
		res += fmt.Sprintf("%dh ", hr%24)
	}
	if min > 0 {
		res += fmt.Sprintf("%dm ", min%60)
	}
	if sec > 0 {
		res += fmt.Sprintf("%ds", sec%60)
	}
	return res
}

type Solution struct {
	// The hash of the solution.
	Hash Uint256 `json:"hash"`
	// The base64-encoded mining payload.
	Preimage []byte `json:"preimage"`
	// The reward to the miner
	Reward SecretWebcash `json:"reward"`
	// The committed difficulty
	Difficulty uint8 `json:"difficulty"`
	// The committed timestamp
	Timestamp time.Time `json:"timestamp"`
}

var g_state_mutex sync.Mutex
var g_settings ProtocolSettings
var g_attempts uint64

type MiningReport struct {
	// The hash of the solution.
	Hash Uint256
	// The base64-encoded mining payload.
	Preimage []byte
}

func (report MiningReport) MarshalJSON() ([]byte, error) {
	// Serialize preimage as string
	preimage, err := json.Marshal(string(report.Preimage))
	if err != nil {
		return nil, err
	}
	// Convert hash to decimal notation
	work := new(big.Int).SetBytes(report.Hash[:]).String()
	// Serialize as JSON
	return []byte(fmt.Sprintf(`{"preimage":%s,"work":%s,"legalese":{"terms":true}}`, string(preimage), string(work))), nil
}

func submit_solution(soln Solution) error {
	const server = "http://127.0.0.1:8000"

	// Serialize the mining report as JSON
	report, err := json.Marshal(MiningReport{
		Hash:     soln.Hash,
		Preimage: soln.Preimage,
	})
	if err != nil {
		// Should never happen!
		fmt.Println("Error: failed to serialize mining report:", err)
		return err
	}

	// Send the mining report to the server
	resp, err := http.Post(server+"/api/v1/mining_report", "application/json", bytes.NewReader(report))
	if err != nil {
		// A network error should not cause us to drop the solution.
		// We requeue the solution to the channel.
		fmt.Println("Error: invalid server response to mining report request:", err)
		return err
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// A malformed server response could also be a transient error.
		// We requeue the solution to the channel.
		fmt.Println("Error: invalid message body in response to mining report request:", err)
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		// The server did not return a JSON object.  Again, we assume
		// this is due to a transient error and requeue the solution.
		fmt.Println("Error: response to mining report request is not a JSON object:", err)
		return err
	}

	// Update difficulty, if necessary
	if difficulty, ok := result["difficulty"]; ok {
		if difficulty, ok := difficulty.(uint8); ok {
			g_state_mutex.Lock()
			old_difficulty := g_settings.Difficulty
			g_settings.Difficulty = difficulty
			g_state_mutex.Unlock()
			if difficulty != old_difficulty {
				fmt.Printf("Difficulty adjustment occured!  Server says difficulty=%d\n", difficulty)
			}
		}
	}

	// Handle server rejection by saving the proof-of-work solution to the
	// orphan log.
	if error, ok := result["error"]; resp.StatusCode != 200 && !(resp.StatusCode == 400 && ok && error == "Didn't use a new secret value.") {
		// Server rejected the solution.  Save it to the orphan log.
		fmt.Println("Server rejected MiningReport:", error, resp)
		// Save the solution to the orphan log
		f, err := os.OpenFile("orphan.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error: failed to open orphan.log:", err)
			// Do not return error to prevent the solution from being requeued.
			return nil
		}
		io.WriteString(f, fmt.Sprintln(soln))
		f.Close()
		// No error is returned to prevent the solution from being requeued.
		return nil
	}

	// Write the claim code for the newly generated coin to the log
	f, err := os.OpenFile("webcash.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error: failed to open webcash.log:", err)
		// Do not return error or else the solution will be requeued.
		return nil
	}
	io.WriteString(f, fmt.Sprintln(soln.Reward))
	f.Close()

	return nil
}

func update_thread(ctx context.Context, solutions chan Solution) {
	// Record start time
	last_settings_fetch := time.Now()

	timeout := 15 * time.Second
	watchdog := time.NewTimer(timeout)

	for {
		// https://medium.com/@oboturov/golang-time-after-is-not-garbage-collected-4cbc94740082
		watchdog.Reset(time.Until(last_settings_fetch.Add(timeout)))

		select {
		case <-ctx.Done():
			fmt.Println("closing update thread")
			return

		case soln := <-solutions:
			// Do not submit work less than the current difficulty
			if soln.Difficulty < g_settings.Difficulty {
				fmt.Println("Ignoring solution as difficulty commitment is too low: (", soln.Difficulty, "<", g_settings.Difficulty, ")")
				continue
			}
			if ApparentDifficulty(soln.Hash) < g_settings.Difficulty {
				fmt.Println("Ignoring solution as apparent difficulty is too low: (", ApparentDifficulty(soln.Hash), "<", g_settings.Difficulty, ")")
				continue
			}

			// Do not submit stale work
			now := time.Now()
			if soln.Timestamp.Before(now.Add(-2 * time.Hour)) {
				fmt.Println("Ignoring solution as timestamp is too old: (", soln.Timestamp, "<", now.Add(-2*time.Hour), ")")
				continue
			}

			// Submit the solution to the server
			if err := submit_solution(soln); err != nil {
				fmt.Println("Possible transient error, or server timeout?  Waiting to re-attempt.")
				go func() {
					// Wait 8 seconds before re-attempting
					time.Sleep(8 * time.Second)
					// Requeue the solution
					solutions <- soln
				}()
				continue
			}

		case <-watchdog.C:
			settings, err := get_protocol_settings()

			// Update the watchdog timer to the current time, before checking
			// the result of the fetch, so that there is a delay between
			// attempts.
			now := time.Now()
			old_last_settings_fetch := last_settings_fetch
			last_settings_fetch = now

			// If we failed to fetch the settings, wait before trying again.
			if err != nil {
				fmt.Println(err)
				continue
			}

			// Update global state
			g_state_mutex.Lock()
			g_settings = settings
			attempts := atomic.SwapUint64(&g_attempts, 0)
			g_state_mutex.Unlock()

			// Record how much time has elapsed since the last update
			elapsed := now.Sub(old_last_settings_fetch)

			// Print the current difficulty and speed
			fmt.Printf("server says difficulty=%v ratio=%v speed=%s expect=%v\n", settings.Difficulty, settings.Ratio, get_speed_string(attempts, elapsed), get_expect_string(attempts, elapsed, settings.Difficulty))
		}
	}
}

func mining_thread(ctx context.Context, id int, solutions chan Solution) {
	// The largest difficulty we will attempt work on.
	const max_difficulty = 50

	// The numbes "000" through "999" concatenated together and encoded into
	// base64.  Any 3 ASCII digits encode to 4 base64 digits, so any number N in
	// this range can be encoded as nonces[4*N : 4*N+4].
	nonces := []byte("" +
		"MDAwMDAxMDAyMDAzMDA0MDA1MDA2MDA3MDA4MDA5MDEwMDExMDEyMDEzMDE0MDE1MDE2MDE3MDE4MDE5" +
		"MDIwMDIxMDIyMDIzMDI0MDI1MDI2MDI3MDI4MDI5MDMwMDMxMDMyMDMzMDM0MDM1MDM2MDM3MDM4MDM5" +
		"MDQwMDQxMDQyMDQzMDQ0MDQ1MDQ2MDQ3MDQ4MDQ5MDUwMDUxMDUyMDUzMDU0MDU1MDU2MDU3MDU4MDU5" +
		"MDYwMDYxMDYyMDYzMDY0MDY1MDY2MDY3MDY4MDY5MDcwMDcxMDcyMDczMDc0MDc1MDc2MDc3MDc4MDc5" +
		"MDgwMDgxMDgyMDgzMDg0MDg1MDg2MDg3MDg4MDg5MDkwMDkxMDkyMDkzMDk0MDk1MDk2MDk3MDk4MDk5" +
		"MTAwMTAxMTAyMTAzMTA0MTA1MTA2MTA3MTA4MTA5MTEwMTExMTEyMTEzMTE0MTE1MTE2MTE3MTE4MTE5" +
		"MTIwMTIxMTIyMTIzMTI0MTI1MTI2MTI3MTI4MTI5MTMwMTMxMTMyMTMzMTM0MTM1MTM2MTM3MTM4MTM5" +
		"MTQwMTQxMTQyMTQzMTQ0MTQ1MTQ2MTQ3MTQ4MTQ5MTUwMTUxMTUyMTUzMTU0MTU1MTU2MTU3MTU4MTU5" +
		"MTYwMTYxMTYyMTYzMTY0MTY1MTY2MTY3MTY4MTY5MTcwMTcxMTcyMTczMTc0MTc1MTc2MTc3MTc4MTc5" +
		"MTgwMTgxMTgyMTgzMTg0MTg1MTg2MTg3MTg4MTg5MTkwMTkxMTkyMTkzMTk0MTk1MTk2MTk3MTk4MTk5" +
		"MjAwMjAxMjAyMjAzMjA0MjA1MjA2MjA3MjA4MjA5MjEwMjExMjEyMjEzMjE0MjE1MjE2MjE3MjE4MjE5" +
		"MjIwMjIxMjIyMjIzMjI0MjI1MjI2MjI3MjI4MjI5MjMwMjMxMjMyMjMzMjM0MjM1MjM2MjM3MjM4MjM5" +
		"MjQwMjQxMjQyMjQzMjQ0MjQ1MjQ2MjQ3MjQ4MjQ5MjUwMjUxMjUyMjUzMjU0MjU1MjU2MjU3MjU4MjU5" +
		"MjYwMjYxMjYyMjYzMjY0MjY1MjY2MjY3MjY4MjY5MjcwMjcxMjcyMjczMjc0Mjc1Mjc2Mjc3Mjc4Mjc5" +
		"MjgwMjgxMjgyMjgzMjg0Mjg1Mjg2Mjg3Mjg4Mjg5MjkwMjkxMjkyMjkzMjk0Mjk1Mjk2Mjk3Mjk4Mjk5" +
		"MzAwMzAxMzAyMzAzMzA0MzA1MzA2MzA3MzA4MzA5MzEwMzExMzEyMzEzMzE0MzE1MzE2MzE3MzE4MzE5" +
		"MzIwMzIxMzIyMzIzMzI0MzI1MzI2MzI3MzI4MzI5MzMwMzMxMzMyMzMzMzM0MzM1MzM2MzM3MzM4MzM5" +
		"MzQwMzQxMzQyMzQzMzQ0MzQ1MzQ2MzQ3MzQ4MzQ5MzUwMzUxMzUyMzUzMzU0MzU1MzU2MzU3MzU4MzU5" +
		"MzYwMzYxMzYyMzYzMzY0MzY1MzY2MzY3MzY4MzY5MzcwMzcxMzcyMzczMzc0Mzc1Mzc2Mzc3Mzc4Mzc5" +
		"MzgwMzgxMzgyMzgzMzg0Mzg1Mzg2Mzg3Mzg4Mzg5MzkwMzkxMzkyMzkzMzk0Mzk1Mzk2Mzk3Mzk4Mzk5" +
		"NDAwNDAxNDAyNDAzNDA0NDA1NDA2NDA3NDA4NDA5NDEwNDExNDEyNDEzNDE0NDE1NDE2NDE3NDE4NDE5" +
		"NDIwNDIxNDIyNDIzNDI0NDI1NDI2NDI3NDI4NDI5NDMwNDMxNDMyNDMzNDM0NDM1NDM2NDM3NDM4NDM5" +
		"NDQwNDQxNDQyNDQzNDQ0NDQ1NDQ2NDQ3NDQ4NDQ5NDUwNDUxNDUyNDUzNDU0NDU1NDU2NDU3NDU4NDU5" +
		"NDYwNDYxNDYyNDYzNDY0NDY1NDY2NDY3NDY4NDY5NDcwNDcxNDcyNDczNDc0NDc1NDc2NDc3NDc4NDc5" +
		"NDgwNDgxNDgyNDgzNDg0NDg1NDg2NDg3NDg4NDg5NDkwNDkxNDkyNDkzNDk0NDk1NDk2NDk3NDk4NDk5" +
		"NTAwNTAxNTAyNTAzNTA0NTA1NTA2NTA3NTA4NTA5NTEwNTExNTEyNTEzNTE0NTE1NTE2NTE3NTE4NTE5" +
		"NTIwNTIxNTIyNTIzNTI0NTI1NTI2NTI3NTI4NTI5NTMwNTMxNTMyNTMzNTM0NTM1NTM2NTM3NTM4NTM5" +
		"NTQwNTQxNTQyNTQzNTQ0NTQ1NTQ2NTQ3NTQ4NTQ5NTUwNTUxNTUyNTUzNTU0NTU1NTU2NTU3NTU4NTU5" +
		"NTYwNTYxNTYyNTYzNTY0NTY1NTY2NTY3NTY4NTY5NTcwNTcxNTcyNTczNTc0NTc1NTc2NTc3NTc4NTc5" +
		"NTgwNTgxNTgyNTgzNTg0NTg1NTg2NTg3NTg4NTg5NTkwNTkxNTkyNTkzNTk0NTk1NTk2NTk3NTk4NTk5" +
		"NjAwNjAxNjAyNjAzNjA0NjA1NjA2NjA3NjA4NjA5NjEwNjExNjEyNjEzNjE0NjE1NjE2NjE3NjE4NjE5" +
		"NjIwNjIxNjIyNjIzNjI0NjI1NjI2NjI3NjI4NjI5NjMwNjMxNjMyNjMzNjM0NjM1NjM2NjM3NjM4NjM5" +
		"NjQwNjQxNjQyNjQzNjQ0NjQ1NjQ2NjQ3NjQ4NjQ5NjUwNjUxNjUyNjUzNjU0NjU1NjU2NjU3NjU4NjU5" +
		"NjYwNjYxNjYyNjYzNjY0NjY1NjY2NjY3NjY4NjY5NjcwNjcxNjcyNjczNjc0Njc1Njc2Njc3Njc4Njc5" +
		"NjgwNjgxNjgyNjgzNjg0Njg1Njg2Njg3Njg4Njg5NjkwNjkxNjkyNjkzNjk0Njk1Njk2Njk3Njk4Njk5" +
		"NzAwNzAxNzAyNzAzNzA0NzA1NzA2NzA3NzA4NzA5NzEwNzExNzEyNzEzNzE0NzE1NzE2NzE3NzE4NzE5" +
		"NzIwNzIxNzIyNzIzNzI0NzI1NzI2NzI3NzI4NzI5NzMwNzMxNzMyNzMzNzM0NzM1NzM2NzM3NzM4NzM5" +
		"NzQwNzQxNzQyNzQzNzQ0NzQ1NzQ2NzQ3NzQ4NzQ5NzUwNzUxNzUyNzUzNzU0NzU1NzU2NzU3NzU4NzU5" +
		"NzYwNzYxNzYyNzYzNzY0NzY1NzY2NzY3NzY4NzY5NzcwNzcxNzcyNzczNzc0Nzc1Nzc2Nzc3Nzc4Nzc5" +
		"NzgwNzgxNzgyNzgzNzg0Nzg1Nzg2Nzg3Nzg4Nzg5NzkwNzkxNzkyNzkzNzk0Nzk1Nzk2Nzk3Nzk4Nzk5" +
		"ODAwODAxODAyODAzODA0ODA1ODA2ODA3ODA4ODA5ODEwODExODEyODEzODE0ODE1ODE2ODE3ODE4ODE5" +
		"ODIwODIxODIyODIzODI0ODI1ODI2ODI3ODI4ODI5ODMwODMxODMyODMzODM0ODM1ODM2ODM3ODM4ODM5" +
		"ODQwODQxODQyODQzODQ0ODQ1ODQ2ODQ3ODQ4ODQ5ODUwODUxODUyODUzODU0ODU1ODU2ODU3ODU4ODU5" +
		"ODYwODYxODYyODYzODY0ODY1ODY2ODY3ODY4ODY5ODcwODcxODcyODczODc0ODc1ODc2ODc3ODc4ODc5" +
		"ODgwODgxODgyODgzODg0ODg1ODg2ODg3ODg4ODg5ODkwODkxODkyODkzODk0ODk1ODk2ODk3ODk4ODk5" +
		"OTAwOTAxOTAyOTAzOTA0OTA1OTA2OTA3OTA4OTA5OTEwOTExOTEyOTEzOTE0OTE1OTE2OTE3OTE4OTE5" +
		"OTIwOTIxOTIyOTIzOTI0OTI1OTI2OTI3OTI4OTI5OTMwOTMxOTMyOTMzOTM0OTM1OTM2OTM3OTM4OTM5" +
		"OTQwOTQxOTQyOTQzOTQ0OTQ1OTQ2OTQ3OTQ4OTQ5OTUwOTUxOTUyOTUzOTU0OTU1OTU2OTU3OTU4OTU5" +
		"OTYwOTYxOTYyOTYzOTY0OTY1OTY2OTY3OTY4OTY5OTcwOTcxOTcyOTczOTc0OTc1OTc2OTc3OTc4OTc5" +
		"OTgwOTgxOTgyOTgzOTg0OTg1OTg2OTg3OTg4OTg5OTkwOTkxOTkyOTkzOTk0OTk1OTk2OTk3OTk4OTk5")

	// Close the JSON object: '}'
	final := []byte("fQ==")

	for {
		select {
		case <-ctx.Done():
			fmt.Println("closing mining thread", id)
			return
		default:
		}

		// Get the current difficulty
		g_state_mutex.Lock()
		settings := g_settings
		g_state_mutex.Unlock()

		// If the difficulty is too high, wait a bit and try again
		if settings.Difficulty > max_difficulty {
			time.Sleep(5 * time.Second)
			continue
		}

		// Generate a random secret using the runtime's CSPRNG.  We don't need
		// to go to excessively paranoid lengths to ensure the secret has good
		// entropy, as the secret is going to be redeemed immediately after the
		// solution is submitted.  18 bytes is 144 bits of preimage security, or
		// 72 bits of collision resistance, which is plenty.
		var sk [18]byte
		_, err := rand.Read(sk[:])
		if err != nil {
			panic(err)
		}
		keep := SecretWebcash{
			Secret: base64.StdEncoding.EncodeToString(sk[:]),
			Amount: settings.TotalReward - settings.ServerSubsidy,
		}

		// Generate another secret for the server subsidy.
		_, err = rand.Read(sk[:])
		if err != nil {
			panic(err)
		}
		subsidy := SecretWebcash{
			Secret: base64.StdEncoding.EncodeToString(sk[:]),
			Amount: settings.ServerSubsidy,
		}

		// Clear the secret from memory
		for i := range sk {
			sk[i] = 0
		}

		// Create the mining payload, a serialized JSON object.
		// The miner won't get this far if the terms of service aren't agreed
		// to, so we can safely hard-code acceptance here.
		now := time.Now()
		μsec := fmt.Sprintf("%06d", now.UnixMicro()%1000000)
		for len(μsec) > 1 && μsec[len(μsec)-1] == '0' {
			μsec = μsec[:len(μsec)-1]
		}
		prefix := []byte(fmt.Sprintf(`{"legalese":{"terms":true},"webcash":["%v","%v"],"subsidy":["%v"],"difficulty":%d,"timestamp":%d.%s,"nonce":`, keep, subsidy, subsidy, settings.Difficulty, now.Unix(), μsec))
		// Extend the prefix to be a multiple of 48 in size...
		for len(prefix)%48 != 47 {
			prefix = append(prefix, ' ')
		}
		prefix = append(prefix, '1')
		// ...which becomes 64 bytes when base64-encoded.
		prefix = []byte(base64.StdEncoding.EncodeToString(prefix))
		// And 64 bytes is the SHA256 block size, so we can compute a midstate
		var midstate C.sha256_ctx_t
		C.sha256_init(&midstate)
		C.sha256_update(&midstate, unsafe.Pointer(&prefix[0]), C.size_t(len(prefix)))

		const W = 25 * 8
		var hashes [W]Uint256
		for i := 0; i < 1000; i++ {
			for j := 0; j < 1000; j += W {
				atomic.AddUint64(&g_attempts, W)

				// Compute W-many hashes at once
				C.sha256_write_and_finalize_many(&midstate, (*C.uint8_t)(&nonces[4*i]), (*C.uint8_t)(&nonces[4*j]), (*C.uint8_t)(&final[0]), (*C.uint8_t)(&hashes[0][0]), W/8)

				for k := 0; k < W; k++ {
					if hashes[k][0] == 0 && hashes[k][1] == 0 {
						if CheckProofOfWork(hashes[k], settings.Difficulty) {
							// We found a solution!
							payload := bytes.Join([][]byte{prefix, nonces[4*i : 4*i+4], nonces[4*(j+k) : 4*(j+k)+4], final}, []byte{})
							fmt.Println("GOT SOLUTION!!!", string(payload), hashes[k])
							solutions <- Solution{
								Hash:       hashes[k],
								Preimage:   payload,
								Reward:     keep,
								Difficulty: settings.Difficulty,
								Timestamp:  now,
							}
						}
					}
				}
			}
		}
	}
}

type LegalTerms struct {
	Terms bool `json:"terms"`
}

type ReplaceWebcash struct {
	Inputs  []SecretWebcash `json:"webcashes"`
	Outputs []SecretWebcash `json:"new_webcashes"`
	Terms   LegalTerms      `json:"legalese"`
}

func submit_replacement(replacement []byte) error {
	const server = "http://127.0.0.1:8000"

	// Send the replacement to the server
	resp, err := http.Post(server+"/api/v1/replace", "application/json", bytes.NewReader(replacement))
	if err != nil {
		// A network error should be reported.
		fmt.Println("Error: invalid server response to replacement request:", err)
		return err
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// A malformed server response could also be a transient error.
		// We requeue the solution to the channel.
		fmt.Println("Error: invalid message body in response to replacement request:", err)
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		// The server did not return a JSON object.  Again, we assume
		// this is due to a transient error and requeue the solution.
		fmt.Println("Error: response to replacement request is not a JSON object:", err)
		return err
	}

	// Check the result
	if string(body) != `{"status":"success"}` {
		fmt.Println("Error: server rejected replacement request:", string(body))
		return err
	}

	return nil
}

var counter uint64 = 0

func benchmark_thread(ctx context.Context, id int, hi_secret SecretWebcash, lo_secret0 SecretWebcash, lo_secret1 SecretWebcash) {
	txs := make([]ReplaceWebcash, 2)
	txs[0].Inputs = []SecretWebcash{hi_secret}
	txs[0].Outputs = []SecretWebcash{lo_secret0, lo_secret1}
	txs[0].Terms.Terms = true
	txs[1].Inputs = []SecretWebcash{lo_secret0, lo_secret1}
	txs[1].Outputs = []SecretWebcash{hi_secret}
	txs[1].Terms.Terms = true
	txs_json := make([][]byte, len(txs))
	for i := range txs {
		var err error
		txs_json[i], err = json.Marshal(txs[i])
		if err != nil {
			panic(err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			fmt.Println("closing mining thread", id)
			return
		default:

			err := submit_replacement(txs_json[0])
			if err != nil {
				panic(err)
			}
			atomic.AddUint64(&counter, 1)
			err = submit_replacement(txs_json[1])
			if err != nil {
				panic(err)
			}
			atomic.AddUint64(&counter, 1)
		}
	}
}

func main() {
	terms, err := GetTermsOfService()
	if err != nil {
		panic(err)
	}
	fmt.Println(terms)

	algo := C.GoString(C.sha256_auto_detect())
	fmt.Println("Using SHA256 algorithm:", algo)

	settings, err := get_protocol_settings()
	if err != nil {
		panic(err)
	}
	fmt.Println(settings)
	g_settings = settings

	ctx, done := context.WithCancel(context.Background())
	defer done() // in case of early exit
	g, gctx := errgroup.WithContext(ctx)

	// goroutine to check for Ctrl-C
	g.Go(func() error {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)

		select {
		case sig := <-c:
			fmt.Println("caught signal", sig)
			done()
		case <-ctx.Done():
		}

		fmt.Println("closing signal handler")
		return gctx.Err()
	})

	solutions := make(chan Solution)

	num_threads := runtime.NumCPU()

	root_secret := SecretWebcash{
		Amount: 190000 * 100000000,
		Secret: "faDOu30cja/Tt28X79d1nanX",
	}

	// Make an array of SecretWebcash structs, one for each CPU core.
	hi_secrets := make([]SecretWebcash, num_threads)
	for i := 0; i < num_threads; i++ {
		data := make([]byte, 16)
		_, err = rand.Read(data[:])
		if err != nil {
			panic(err)
		}
		hi_secrets[i].Amount = 2
		hi_secrets[i].Secret = base64.StdEncoding.EncodeToString(data[:])
	}

	// Make an array of SecretWebcash structs, two for each CPU core.
	lo_secrets := make([]SecretWebcash, 2*num_threads)
	for i := 0; i < 2*num_threads; i++ {
		data := make([]byte, 16)
		_, err = rand.Read(data[:])
		if err != nil {
			panic(err)
		}
		lo_secrets[i].Amount = 1
		lo_secrets[i].Secret = base64.StdEncoding.EncodeToString(data[:])
	}

	extra_secret := SecretWebcash{
		Amount: (Amount)(190000*100000000 - 2*num_threads),
		Secret: "extra-secret",
	}

	replace := ReplaceWebcash{
		Inputs:  make([]SecretWebcash, 0),
		Outputs: make([]SecretWebcash, 0),
		Terms:   LegalTerms{Terms: true},
	}
	replace.Inputs = append(replace.Inputs, root_secret)
	for i := 0; i < num_threads; i++ {
		replace.Outputs = append(replace.Outputs, hi_secrets[i])
	}
	replace.Outputs = append(replace.Outputs, extra_secret)

	// Serialize the replacement as JSON
	replace_json, err := json.Marshal(replace)
	if err != nil {
		// Should never happen!
		panic(err)
	}

	err = submit_replacement(replace_json)
	if err != nil {
		panic(err)
	}

	// goroutine which periodically queries the webcash server for change in
	// difficulty or subsidy, and submits solution mining reports.
	g.Go(func() error {
		update_thread(gctx, solutions)
		return nil
	})

	// goroutine which performs mining
	for i := 0; i < num_threads; i++ {
		id := i
		g.Go(func() error {
			//mining_thread(gctx, id, solutions)
			benchmark_thread(gctx, id, hi_secrets[id], lo_secrets[2*id], lo_secrets[2*id+1])
			return nil
		})
	}

	// wait for all goroutines to exit
	err = g.Wait()
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("all goroutines exited")
	}

	// Move the webcash back to the original secret.
	replace.Inputs = make([]SecretWebcash, 0)
	replace.Outputs = make([]SecretWebcash, 0)
	for i := 0; i < num_threads; i++ {
		replace.Inputs = append(replace.Inputs, hi_secrets[i])
	}
	replace.Inputs = append(replace.Inputs, extra_secret)
	replace.Outputs = append(replace.Outputs, root_secret)

	// Serialize the replacement as JSON
	replace_json, err = json.Marshal(replace)
	if err != nil {
		// Should never happen!
		panic(err)
	}

	err = submit_replacement(replace_json)
	if err != nil {
		panic(err)
	}

	fmt.Println("done", counter, "replacement transactions")
}
