package common

type KeyPair struct {
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	PublicKey           string `json:"publicKey"`
}

type RegisterModel struct {
	Name               string  `json:"name"`
	Email              string  `json:"email"`
	MasterPasswordHash string  `json:"masterPasswordHash"`
	MasterPasswordHint string  `json:"masterPasswordHint"`
	Key                string  `json:"key"`
	Keys               KeyPair `json:"keys"`
	Token              string  `json:"token"`
	OrganizationUserId uint64  `json:"organizationUserId"`
	Kdf                int     `json:"kdf"`
	KdfIterations      int     `json:"kdfIterations"`
}

type TokenModel struct {
	ClientId     string `json:"client_id"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"Key"`
	PrivateKey   string `json:"PrivateKey,omitempty"`
}
