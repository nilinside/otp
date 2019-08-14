package yubikey

import (
	"encoding/hex"
	"github.com/conformal/yubikey"
	"log"
)

type Validator struct {
	Passcode string         `json:"passcode"`
	Secret   string         `json:"Secret"`
	Counter  uint64         `json:"counter"`
	Session  uint64         `json:"session"`
	Token    *yubikey.Token `json:"token"`
}

func (v *Validator) Validate() bool {
	secretKey, err := v.getSecretKey(v.Secret)
	if err != nil {
		return false
	}
	err = v.getToken(v.Passcode, secretKey)
	if err != nil {
		return false
	}
	log.Printf("%+v", v.Token)
	log.Print(v.Token.Use, v.Counter)

	if v.Token.Ctr < uint16(v.Counter) {
		return false
	} else if v.Token.Ctr == uint16(v.Counter) && v.Token.Use <= uint8(v.Session) {
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
