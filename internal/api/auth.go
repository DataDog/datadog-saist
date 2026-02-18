package api

import (
	"os"
)

const defaultDatadogSite = "datadoghq.com"

type DatadogAuth struct {
	Site     string
	AppKey   *string
	ApiKey   *string
	JWTToken *string
}

func GetDatadogAuth() (DatadogAuth, error) {
	ddSiteFromEnv := os.Getenv("DD_SITE")
	ddSite := defaultDatadogSite
	var apiKey *string = nil
	var appKey *string = nil
	var jwtToken *string = nil
	if ddSiteFromEnv != "" {
		ddSite = ddSiteFromEnv
	}

	ddAppKey := os.Getenv("DD_APP_KEY")
	if ddAppKey != "" {
		appKey = &ddAppKey
	}

	ddApiKey := os.Getenv("DD_API_KEY")
	if ddApiKey != "" {
		apiKey = &ddApiKey
	}

	ddJWTToken := os.Getenv("DD_JWT_TOKEN")
	if ddJWTToken != "" {
		jwtToken = &ddJWTToken
	}

	return DatadogAuth{
		Site:     ddSite,
		AppKey:   appKey,
		ApiKey:   apiKey,
		JWTToken: jwtToken,
	}, nil
}

func (auth *DatadogAuth) HasAPIKeyAuth() bool {
	return auth.ApiKey != nil && auth.AppKey != nil
}

func (auth *DatadogAuth) HasJWTAuth() bool {
	return auth.JWTToken != nil
}

func (auth *DatadogAuth) HasAnyAuth() bool {
	return auth.HasAPIKeyAuth() || auth.HasJWTAuth()
}
