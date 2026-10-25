package suite

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Device identifiers (IMEI, IMSI, ICCID, MEID, serial numbers, phone
// numbers, hardware addresses, UDIDs) are kept verbatim only in the
// sealed original. Normalized output — events, entity attributes, case
// notes — carries them masked with the derivative-redaction marker
// format (internal/redact.Marker): [REDACTED:<category>:<8 hex of the
// value's SHA-256>]. Two masks of the same value compare equal, so an
// examiner can still link a device across reports, and anyone holding a
// candidate value can confirm it; the value itself is not repeated.
//
// The marker is built here rather than by importing internal/redact:
// that package pulls in the detection code, and the parser fingerprint
// must not change whenever a detection rule does. A test pins the two
// formats together.

var idCategories = []struct {
	re  *regexp.Regexp
	cat string
}{
	{regexp.MustCompile(`(?i)imei`), "imei"},
	{regexp.MustCompile(`(?i)imsi`), "imsi"},
	{regexp.MustCompile(`(?i)iccid`), "iccid"},
	{regexp.MustCompile(`MEID|(?i:\bmeid\b)`), "meid"},
	{regexp.MustCompile(`(?i)udid|unique ?device ?id`), "udid"},
	{regexp.MustCompile(`(?i)serial`), "serial"},
	{regexp.MustCompile(`(?i)msisdn|phone ?number|phonenumber|mdn\b`), "phone"},
	{regexp.MustCompile(`(?i)mac ?address|macaddress|wi-?fi ?address|bluetooth ?address|bt ?address`), "mac"},
}

// idCategory names the identifier category a field/item name holds, or "".
func idCategory(name string) string {
	for _, c := range idCategories {
		if c.re.MatchString(name) {
			return c.cat
		}
	}
	return ""
}

// marker masks a value; it matches internal/redact.Marker.
func marker(cat, value string) string {
	sum := sha256.Sum256([]byte(value))
	return "[REDACTED:" + cat + ":" + hex.EncodeToString(sum[:4]) + "]"
}

// maskField returns value masked when the field name is a device
// identifier, and the value unchanged otherwise.
func maskField(name, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	if cat := idCategory(name); cat != "" {
		return marker(cat, value)
	}
	return value
}
