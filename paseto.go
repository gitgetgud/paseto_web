package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"aidanwoods.dev/go-paseto"
)

// EncodeRequest represents a request to encode a PASETO token
type EncodeRequest struct {
	Version string                 `json:"version"` // v2, v3, v4
	Purpose string                 `json:"purpose"` // local or public
	Payload map[string]interface{} `json:"payload"`
	Key     string                 `json:"key"`    // hex-encoded key
	Footer  string                 `json:"footer"` // optional footer
}

// EncodeResponse represents the response from encoding
type EncodeResponse struct {
	Token string `json:"token"`
}

// DecodeRequest represents a request to decode a PASETO token
type DecodeRequest struct {
	Token   string `json:"token"`
	Key     string `json:"key"`     // hex-encoded key
	Version string `json:"version"` // optional, auto-detect from token
	Purpose string `json:"purpose"` // optional, auto-detect from token
}

// DecodeResponse represents the response from decoding
type DecodeResponse struct {
	Payload map[string]interface{} `json:"payload"`
	Footer  string                 `json:"footer"`
}

// GenerateKeysRequest represents a request to generate keys
type GenerateKeysRequest struct {
	Version string `json:"version"` // v2, v3, v4
	Purpose string `json:"purpose"` // local or public
}

// GenerateKeysResponse represents the response from key generation
type GenerateKeysResponse struct {
	SymmetricKey string `json:"symmetricKey,omitempty"`
	SecretKey    string `json:"secretKey,omitempty"`
	PublicKey    string `json:"publicKey,omitempty"`
}

// EncodePaseto creates a PASETO token from the given request
func EncodePaseto(req EncodeRequest) (*EncodeResponse, error) {
	token := paseto.NewToken()

	// Set claims from payload
	for key, value := range req.Payload {
		if err := token.Set(key, value); err != nil {
			return nil, fmt.Errorf("failed to set claim %s: %w", key, err)
		}
	}

	// Set footer if provided
	if req.Footer != "" {
		token.SetFooter([]byte(req.Footer))
	}

	var tokenString string
	var err error

	switch req.Version {
	case "v2":
		tokenString, err = encodeV2(token, req.Purpose, req.Key)
	case "v3":
		tokenString, err = encodeV3(token, req.Purpose, req.Key)
	case "v4":
		tokenString, err = encodeV4(token, req.Purpose, req.Key)
	default:
		return nil, fmt.Errorf("unsupported version: %s", req.Version)
	}

	if err != nil {
		return nil, err
	}

	return &EncodeResponse{Token: tokenString}, nil
}

func encodeV2(token paseto.Token, purpose, keyHex string) (string, error) {
	switch purpose {
	case "local":
		key, err := paseto.V2SymmetricKeyFromHex(keyHex)
		if err != nil {
			return "", fmt.Errorf("invalid symmetric key: %w", err)
		}
		return token.V2Encrypt(key), nil
	case "public":
		key, err := paseto.NewV2AsymmetricSecretKeyFromHex(keyHex)
		if err != nil {
			return "", fmt.Errorf("invalid secret key: %w", err)
		}
		return token.V2Sign(key), nil
	default:
		return "", fmt.Errorf("unsupported purpose: %s", purpose)
	}
}

func encodeV3(token paseto.Token, purpose, keyHex string) (string, error) {
	switch purpose {
	case "local":
		key, err := paseto.V3SymmetricKeyFromHex(keyHex)
		if err != nil {
			return "", fmt.Errorf("invalid symmetric key: %w", err)
		}
		return token.V3Encrypt(key, nil), nil
	case "public":
		key, err := paseto.NewV3AsymmetricSecretKeyFromHex(keyHex)
		if err != nil {
			return "", fmt.Errorf("invalid secret key: %w", err)
		}
		return token.V3Sign(key, nil), nil
	default:
		return "", fmt.Errorf("unsupported purpose: %s", purpose)
	}
}

func encodeV4(token paseto.Token, purpose, keyHex string) (string, error) {
	switch purpose {
	case "local":
		key, err := paseto.V4SymmetricKeyFromHex(keyHex)
		if err != nil {
			return "", fmt.Errorf("invalid symmetric key: %w", err)
		}
		return token.V4Encrypt(key, nil), nil
	case "public":
		key, err := paseto.NewV4AsymmetricSecretKeyFromHex(keyHex)
		if err != nil {
			return "", fmt.Errorf("invalid secret key: %w", err)
		}
		return token.V4Sign(key, nil), nil
	default:
		return "", fmt.Errorf("unsupported purpose: %s", purpose)
	}
}

// DecodePaseto decodes a PASETO token
func DecodePaseto(req DecodeRequest) (*DecodeResponse, error) {
	// Auto-detect version and purpose from token if not provided
	version, purpose := req.Version, req.Purpose
	if version == "" || purpose == "" {
		detectedVersion, detectedPurpose, err := detectTokenType(req.Token)
		if err != nil {
			return nil, err
		}
		if version == "" {
			version = detectedVersion
		}
		if purpose == "" {
			purpose = detectedPurpose
		}
	}

	var token *paseto.Token
	var err error

	parser := paseto.NewParserWithoutExpiryCheck()

	switch version {
	case "v2":
		token, err = decodeV2(parser, req.Token, purpose, req.Key)
	case "v3":
		token, err = decodeV3(parser, req.Token, purpose, req.Key)
	case "v4":
		token, err = decodeV4(parser, req.Token, purpose, req.Key)
	default:
		return nil, fmt.Errorf("unsupported version: %s", version)
	}

	if err != nil {
		return nil, err
	}

	// Extract claims
	var payload map[string]interface{}
	if err := json.Unmarshal(token.ClaimsJSON(), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &DecodeResponse{
		Payload: payload,
		Footer:  string(token.Footer()),
	}, nil
}

func detectTokenType(tokenString string) (version, purpose string, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 3 {
		return "", "", fmt.Errorf("invalid token format")
	}

	version = parts[0]
	purpose = parts[1]

	if version != "v2" && version != "v3" && version != "v4" {
		return "", "", fmt.Errorf("unsupported version: %s", version)
	}

	if purpose != "local" && purpose != "public" {
		return "", "", fmt.Errorf("unsupported purpose: %s", purpose)
	}

	return version, purpose, nil
}

func decodeV2(parser paseto.Parser, tokenString, purpose, keyHex string) (*paseto.Token, error) {
	switch purpose {
	case "local":
		key, err := paseto.V2SymmetricKeyFromHex(keyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid symmetric key: %w", err)
		}
		return parser.ParseV2Local(key, tokenString)
	case "public":
		key, err := paseto.NewV2AsymmetricPublicKeyFromHex(keyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid public key: %w", err)
		}
		return parser.ParseV2Public(key, tokenString)
	default:
		return nil, fmt.Errorf("unsupported purpose: %s", purpose)
	}
}

func decodeV3(parser paseto.Parser, tokenString, purpose, keyHex string) (*paseto.Token, error) {
	switch purpose {
	case "local":
		key, err := paseto.V3SymmetricKeyFromHex(keyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid symmetric key: %w", err)
		}
		return parser.ParseV3Local(key, tokenString, nil)
	case "public":
		key, err := paseto.NewV3AsymmetricPublicKeyFromHex(keyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid public key: %w", err)
		}
		return parser.ParseV3Public(key, tokenString, nil)
	default:
		return nil, fmt.Errorf("unsupported purpose: %s", purpose)
	}
}

func decodeV4(parser paseto.Parser, tokenString, purpose, keyHex string) (*paseto.Token, error) {
	switch purpose {
	case "local":
		key, err := paseto.V4SymmetricKeyFromHex(keyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid symmetric key: %w", err)
		}
		return parser.ParseV4Local(key, tokenString, nil)
	case "public":
		key, err := paseto.NewV4AsymmetricPublicKeyFromHex(keyHex)
		if err != nil {
			return nil, fmt.Errorf("invalid public key: %w", err)
		}
		return parser.ParseV4Public(key, tokenString, nil)
	default:
		return nil, fmt.Errorf("unsupported purpose: %s", purpose)
	}
}

// GenerateKeys generates new keys for the specified version and purpose
func GenerateKeys(req GenerateKeysRequest) (*GenerateKeysResponse, error) {
	switch req.Version {
	case "v2":
		return generateV2Keys(req.Purpose)
	case "v3":
		return generateV3Keys(req.Purpose)
	case "v4":
		return generateV4Keys(req.Purpose)
	default:
		return nil, fmt.Errorf("unsupported version: %s", req.Version)
	}
}

func generateV2Keys(purpose string) (*GenerateKeysResponse, error) {
	switch purpose {
	case "local":
		key := paseto.NewV2SymmetricKey()
		return &GenerateKeysResponse{
			SymmetricKey: key.ExportHex(),
		}, nil
	case "public":
		secretKey := paseto.NewV2AsymmetricSecretKey()
		publicKey := secretKey.Public()
		return &GenerateKeysResponse{
			SecretKey: secretKey.ExportHex(),
			PublicKey: publicKey.ExportHex(),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported purpose: %s", purpose)
	}
}

func generateV3Keys(purpose string) (*GenerateKeysResponse, error) {
	switch purpose {
	case "local":
		key := paseto.NewV3SymmetricKey()
		return &GenerateKeysResponse{
			SymmetricKey: key.ExportHex(),
		}, nil
	case "public":
		secretKey := paseto.NewV3AsymmetricSecretKey()
		publicKey := secretKey.Public()
		return &GenerateKeysResponse{
			SecretKey: secretKey.ExportHex(),
			PublicKey: publicKey.ExportHex(),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported purpose: %s", purpose)
	}
}

func generateV4Keys(purpose string) (*GenerateKeysResponse, error) {
	switch purpose {
	case "local":
		key := paseto.NewV4SymmetricKey()
		return &GenerateKeysResponse{
			SymmetricKey: key.ExportHex(),
		}, nil
	case "public":
		secretKey := paseto.NewV4AsymmetricSecretKey()
		publicKey := secretKey.Public()
		return &GenerateKeysResponse{
			SecretKey: secretKey.ExportHex(),
			PublicKey: publicKey.ExportHex(),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported purpose: %s", purpose)
	}
}
