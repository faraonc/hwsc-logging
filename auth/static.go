package auth

import (
	"bytes"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	pbauth "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
	"github.com/hwsc-org/hwsc-lib/consts"
	"github.com/hwsc-org/hwsc-lib/validation"
	"hash"
	"strings"
	"sync"
	"time"
)

const (
	utc = "UTC"
)

var (
	keyGenLocker       sync.Mutex
	emailTokenByteSize = 32
	daysInTwoWeeks     = 14
)

// ValidateIdentification validates Identification along with the embedded Secret.
// Checks if the Secret has expired.
// Returns the first error encountered.
func ValidateIdentification(id *pbauth.Identification) error {
	if id == nil {
		return consts.ErrNilIdentification
	}
	if strings.TrimSpace(id.GetToken()) == "" {
		return consts.ErrEmptyToken
	}
	if err := ValidateSecret(id.GetSecret()); err != nil {
		return err
	}
	return nil
}

// ValidateHeader validates Header.
// Returns the first error encountered.
func ValidateHeader(header *Header) error {
	if header == nil {
		return consts.ErrNilHeader
	}
	tokenType := header.TokenTyp
	if tokenType < NoType || tokenType > Jet {
		return consts.ErrUnknownTokenType
	}
	alg := header.Alg
	if alg < NoAlg || alg > Hs512 {
		return consts.ErrUnknownAlgorithm
	}
	return nil
}

// ValidateBody validates Body.
// Checks if token string has expired.
// Returns the first error encountered.
func ValidateBody(body *Body) error {
	if body == nil {
		return consts.ErrNilBody
	}
	if err := validation.ValidateUserUUID(body.UUID); err != nil {
		return err
	}
	permission := body.Permission
	if permission < NoPermission || permission > Admin {
		return consts.ErrUnknownPermission
	}
	if isExpired(body.ExpirationTimestamp) {
		return consts.ErrExpiredBody
	}
	return nil
}

// ValidateSecret checks if the secret is still valid and has not expired.
// Returns an error if the Secret is not valid and has expired.
func ValidateSecret(secret *pbauth.Secret) error {
	if secret == nil {
		return consts.ErrNilSecret
	}
	if strings.TrimSpace(secret.Key) == "" {
		return consts.ErrEmptySecret
	}
	createTime := secret.CreatedTimestamp
	if createTime == 0 || createTime > time.Now().UTC().Unix() {
		return consts.ErrInvalidSecretCreateTimestamp
	}
	if isExpired(secret.ExpirationTimestamp) {
		return consts.ErrExpiredSecret
	}
	return nil
}

func isExpired(timestamp int64) bool {
	if timestamp <= 0 || time.Now().UTC().Unix() >= timestamp {
		return true
	}
	return false
}

// NewToken generates token string using a header, body, and secret.
// Return error if an error exists during signing.
func NewToken(header *Header, body *Body, secret *pbauth.Secret) (string, error) {
	if err := ValidateHeader(header); err != nil {
		return "", err
	}
	if err := ValidateBody(body); err != nil {
		return "", err
	}
	if err := ValidateSecret(secret); err != nil {
		return "", err
	}
	if body.Permission == Admin && header.Alg != Hs512 {
		return "", consts.ErrInvalidPermission
	}
	// Currently supports JWT, JET
	if header.TokenTyp != Jwt && header.TokenTyp != Jet {
		return "", consts.ErrUnknownTokenType
	}
	tokenString, err := getTokenSignature(header, body, secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// getTokenSignature gets the token signature using the encoded header, body, and secret key.
// Return error if an error exists during signing.
func getTokenSignature(header *Header, body *Body, secret *pbauth.Secret) (string, error) {
	if err := ValidateHeader(header); err != nil {
		return "", err
	}
	if err := ValidateBody(body); err != nil {
		return "", err
	}
	if err := ValidateSecret(secret); err != nil {
		return "", err
	}
	if body.Permission == Admin && header.Alg != Hs512 {
		return "", consts.ErrInvalidPermission
	}
	if header.TokenTyp != Jwt && header.TokenTyp != Jet {
		return "", consts.ErrUnknownTokenType
	}
	// Token Signature = <encoded header>.<encoded body>.<hashed(<encoded header>.<encoded body>)>
	// 1. Encode the header
	encodedHeader, err := base64Encode(header)
	if err != nil {
		return "", err
	}
	// 2. Encode the body
	encodedBody, err := base64Encode(body)
	if err != nil {
		return "", err
	}
	// 3. Build <encoded header>.<encoded body>
	// 4. Build <hashed(<encoded header>.<encoded body>)>
	// 5. Build Token Signature = <encoded header>.<encoded body>.<hashed(<encoded header>.<encoded body>)>
	return buildTokenSignature(encodedHeader, encodedBody, header.Alg, secret)
}

// buildTokenSignature builds the token signature using the encoded header, body, selected algorithm, and secret key.
// Return error if an error exists during signing.
func buildTokenSignature(encodedHeader string, encodedBody string, alg Algorithm, secret *pbauth.Secret) (string, error) {
	if strings.TrimSpace(encodedHeader) == "" {
		return "", consts.ErrInvalidEncodedHeader
	}
	if strings.TrimSpace(encodedBody) == "" {
		return "", consts.ErrInvalidEncodedBody
	}
	if err := ValidateSecret(secret); err != nil {
		return "", err
	}
	// 3. Build <encoded header>.<encoded body>
	var bufferHeaderBody bytes.Buffer
	bufferHeaderBody.WriteString(encodedHeader)
	bufferHeaderBody.WriteString(".")
	bufferHeaderBody.WriteString(encodedBody)
	encodedHeaderBody := bufferHeaderBody.String()
	// 4. Build <hashed(<encoded header>.<encoded body>)>
	encodedSignature, err := hashSignature(alg, encodedHeaderBody, secret)
	if err != nil {
		return "", nil
	}
	// 5. Build Token Signature = <encoded header>.<encoded body>.<hashed(<encoded header>.<encoded body>)>
	var bufferTokenSignature bytes.Buffer
	bufferTokenSignature.WriteString(encodedHeaderBody)
	bufferTokenSignature.WriteString(".")
	bufferTokenSignature.WriteString(encodedSignature)
	return bufferTokenSignature.String(), nil
}

// base64Encode takes in a interface and encodes it as a string.
// Returns a base 64 encoded string or error during marshalling.
func base64Encode(src interface{}) (string, error) {
	if src == nil {
		return "", consts.ErrNilInterface
	}
	srcMarshal, err := json.Marshal(src)
	if err != nil {
		return "", err
	}
	srcString := string(srcMarshal)
	// TODO maybe use Trim
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(srcString)), "="), nil
}

// base64Encode takes in a base 64 encoded string.
// Returns the actual string or an error of it fails to decode the string.
func base64Decode(src string) (string, error) {
	if strings.TrimSpace(src) == "" {
		return "", consts.ErrEmptyString
	}
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(src)
	if err != nil {
		errMsg := fmt.Errorf("decoding error %s", err)
		return "", errMsg
	}
	return string(decoded), nil
}

// hashSignature generates a HMAC hash of a string using a secret
func hashSignature(alg Algorithm, signatureValue string, secret *pbauth.Secret) (string, error) {
	if strings.TrimSpace(signatureValue) == "" {
		return "", consts.ErrInvalidSignatureValue
	}
	if err := ValidateSecret(secret); err != nil {
		return "", err
	}
	key := []byte(secret.Key)
	var h hash.Hash
	switch alg {
	case Hs256:
		h = hmac.New(sha256.New, key)
	case Hs512:
		h = hmac.New(sha512.New, key)
	default:
		return "", consts.ErrNoHashAlgorithm
	}
	h.Write([]byte(signatureValue))
	return base64.URLEncoding.EncodeToString(h.Sum(nil)), nil
}

// isEquivalentHash validates a hash against a value
func isEquivalentHash(alg Algorithm, signatureValue string, secret *pbauth.Secret, hashedValue string) bool {
	if err := ValidateSecret(secret); err != nil {
		return false
	}
	/*
		hashSignature cannot be reversed all you can do is hash the same character and compare it with a hashed value.
		If it evaluates to true, then the character is a what is in the hash.
		The isValidHash function only hashes the value with the secret and compared it with the hash.
	*/
	actualHashedValue, err := hashSignature(alg, signatureValue, secret)
	if err != nil {
		return false
	}
	return hashedValue == actualHashedValue
}

// ExtractUUID takes in a token string and extracts the UUID from the body.
// Returns the uuid or an empty string due to an error.
func ExtractUUID(tokenString string) string {
	tokenSignature := strings.Split(tokenString, ".")
	if len(tokenSignature) != 3 {
		return ""
	}
	decodedBody, err := base64Decode(tokenSignature[1])
	if err != nil {
		return ""
	}
	body := &Body{}
	if err := json.Unmarshal([]byte(decodedBody), body); err != nil {
		return ""
	}
	if body == nil {
		return ""
	}
	if err := validation.ValidateUserUUID(body.UUID); err != nil {
		return ""
	}
	return body.UUID
}

// generateSecretKey generates a base64 URL-safe string
// built from securely generated random bytes.
// Number of bytes is determined by tokenSize.
// Return error if system's secure random number generator fails.
// TODO: testing
func generateSecretKey(tokenSize int) (string, error) {
	if tokenSize <= 0 {
		return "", consts.ErrInvalidTokenSize
	}

	keyGenLocker.Lock()
	defer keyGenLocker.Unlock()

	randomBytes := make([]byte, tokenSize)
	_, err := cryptorand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(randomBytes), nil
}

// generateExpirationTimestamp returns the expiration date set with addDays parameter.
// Currently only adds number of days to currentTimestamp.
// Returns error if date object is nil or error with loading location.
// TODO: testing
func generateExpirationTimestamp(currentTimestamp time.Time, addDays int) (*time.Time, error) {
	if currentTimestamp.IsZero() {
		return nil, consts.ErrInvalidTimeStamp
	}

	if addDays <= 0 {
		return nil, consts.ErrInvalidNumberOfDays
	}

	timeZonedTimestamp := currentTimestamp
	if currentTimestamp.Location().String() != utc {
		timeZonedTimestamp = currentTimestamp.UTC()
	}

	// addDays to current weekday to get to addDays later
	// ie: adding 7 days to current weekday gets you one week later timestamp
	modifiedTimestamp := timeZonedTimestamp.AddDate(0, 0, addDays)

	// reset time to 3 AM
	expirationTimestamp := time.Date(modifiedTimestamp.Year(), modifiedTimestamp.Month(), modifiedTimestamp.Day(),
		3, 0, 0, 0, timeZonedTimestamp.Location())

	return &expirationTimestamp, nil
}

// GenerateEmailIdentification takes the user's uuid and permission to generate an email token for verification.
// Returns an identification containing the secret and token string.
// TODO: testing
func GenerateEmailIdentification(uuid string, permission string) (*pbauth.Identification, error) {
	if err := validation.ValidateUserUUID(uuid); err != nil {
		return nil, err
	}
	permissionLevel, ok := PermissionEnumMap[permission]
	if !ok {
		return nil, consts.ErrInvalidPermission
	}
	emailSecretKey, err := generateSecretKey(emailTokenByteSize)
	if err != nil {
		return nil, err
	}
	// subtract a second because the test runs fast causing our check to fail
	emailTokenCreationTime := time.Now().UTC().Add(time.Duration(-1) * time.Second)
	emailTokenExpirationTime, err := generateExpirationTimestamp(emailTokenCreationTime, daysInTwoWeeks)
	if err != nil {
		return nil, err
	}

	header := &Header{
		Alg:      AlgorithmMap[UserRegistration],
		TokenTyp: Jet,
	}
	body := &Body{
		UUID:                uuid,
		Permission:          permissionLevel,
		ExpirationTimestamp: emailTokenExpirationTime.Unix(),
	}
	secret := &pbauth.Secret{
		Key:                 emailSecretKey,
		CreatedTimestamp:    emailTokenCreationTime.Unix(),
		ExpirationTimestamp: emailTokenExpirationTime.Unix(),
	}
	emailToken, err := NewToken(header, body, secret)
	if err != nil {
		return nil, err
	}

	return &pbauth.Identification{
		Token:  emailToken,
		Secret: secret,
	}, nil
}
