package openid

type Config struct {
	BaseURL         string
	IssuerURL       string
	RedirectURL     string
	ClientID        string
	ClientSecret    string
	Scopes          []string
	Groups          []string
	ServiceAccounts []string
}
