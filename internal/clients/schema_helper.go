package clients

import "github.com/invopop/jsonschema"

func GenerateSchema[T any]() interface{} {
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false, // Required by OpenAI
		DoNotReference:            true,  // Ensures a flat, readable schema
	}
	var v T
	return reflector.Reflect(v)
}
