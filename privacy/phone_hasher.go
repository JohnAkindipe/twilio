package privacy

import (
	"crypto/sha256"
	"encoding/hex"
)

type Hasher struct {
	analyticsSalt string
	logSalt       string
}

func NewHasher(analyticsSalt, logSalt string) *Hasher {
	return &Hasher{
		analyticsSalt: analyticsSalt,
		logSalt:       logSalt,
	}
}

// hashPhoneNumber creates a privacy-preserving hash of a phone number.
// It uses SHA256 with a configured salt to prevent rainbow table attacks.
// omitting the salt will return an unsalted hash.
func hashPhoneNumber(phoneNumber string, salt string) string {
	if phoneNumber == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(phoneNumber + salt))
	return hex.EncodeToString(h.Sum(nil))
}

// ConstructUserId returns a salted hash of the phone for analytics user identification.
func (h *Hasher) ConstructUserId(phoneNumber string) string {
	return hashPhoneNumber(phoneNumber, h.analyticsSalt)
}

// HashForLogs returns a salted hash of the phone for safe log output.
// If the log salt is omitted, an unsalted hash is returned.
func (h *Hasher) HashForLogs(phoneNumber string) string {
	return hashPhoneNumber(phoneNumber, h.logSalt)
}
