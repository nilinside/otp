package yubikey

import (
	"encoding/hex"
	"github.com/conformal/yubikey"
	"github.com/nilinside/otp"
	"net/url"
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
	_, o, err := yubikey.ParseOTPString(otpString)
	if err != nil {
		return err
	}
	t, err := o.Parse(*priv)
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

//todo::generate keyUrl
type GenerateOpts struct {
	// Name of the issuing Organization/Company.
	Issuer string
	// Name of the User's Account (eg, email address)
	AccountName string
	// Secret to store. Defaults to a randomly generated secret of SecretSize.  You should generally leave this empty.
	Secret string
	// Digits to request. Defaults to 6.
	Digits otp.Digits
	// Algorithm to use for HMAC. Defaults to SHA1.
	Algorithm otp.Algorithm
}

func Generate(opts GenerateOpts) (*otp.Key, error) {
	// url encode the Issuer/AccountName
	if opts.Issuer == "" {
		return nil, otp.ErrGenerateMissingIssuer
	}

	if opts.AccountName == "" {
		return nil, otp.ErrGenerateMissingAccountName
	}
	v := url.Values{}
	v.Set("issuer", opts.Issuer)
	v.Set("secret", opts.Secret)
	u := url.URL{
		Scheme:   "otpauth",
		Host:     "yubikey",
		Path:     "/" + opts.Issuer + ":" + opts.AccountName,
		RawQuery: v.Encode(),
	}
	return otp.NewKeyFromURL(u.String())
}

func NewValidator(secret string, counter uint64, use uint64) *Validator {
	return &Validator{
		Secret:  secret,
		Counter: counter,
		Use:     use,
	}
}
