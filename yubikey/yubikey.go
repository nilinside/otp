package yubikey

import (
	"encoding/hex"
	"github.com/conformal/yubikey"
)

type Validator struct {
	Secret  string
	Counter uint64
	Use     uint64
	Token   *yubikey.Token
}

func (v *Validator) Validate(passcode string) bool {
	secretKey, err := v.getSecretKey(v.Secret)
	if err != nil {
		return false
	}
	err = v.getToken(passcode, secretKey)
	if err != nil {
		return false
	}

	if v.Token.Ctr < uint16(v.Counter) {
		return false
	} else if v.Token.Ctr == uint16(v.Counter) && v.Token.Use <= uint8(v.Use) {
		return false
	}

	return true
}

func (v *Validator) getToken(otpString string, priv *yubikey.Key) error {
	_, otp, err := yubikey.ParseOTPString(otpString)
	if err != nil {
		return err
	}
	t, err := otp.Parse(*priv)
	if err != nil {
		return err
	}
	v.Token = t
	return nil
}

func (v *Validator) getSecretKey(key string) (*yubikey.Key, error) {
	b, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	priv := yubikey.NewKey(b)

	return &priv, nil
}

func NewValidator(secret string, counter uint64, use uint64) *Validator {
	return &Validator{
		Secret:  secret,
		Counter: counter,
		Use:     use,
	}
}
