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

// GenerateSchemaWithAnyOf converts disjoint oneOf unions to anyOf unions for
// strict response format providers that support anyOf but reject oneOf.
func GenerateSchemaWithAnyOf[T any]() interface{} {
	schema := GenerateSchema[T]().(*jsonschema.Schema)
	convertOneOfToAnyOf(schema)
	return schema
}

func convertOneOfToAnyOf(schema *jsonschema.Schema) {
	if schema == nil {
		return
	}
	if len(schema.OneOf) > 0 {
		schema.AnyOf = append(schema.AnyOf, schema.OneOf...)
		schema.OneOf = nil
	}
	for _, child := range schema.AllOf {
		convertOneOfToAnyOf(child)
	}
	for _, child := range schema.AnyOf {
		convertOneOfToAnyOf(child)
	}
	if schema.Properties != nil {
		for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
			convertOneOfToAnyOf(pair.Value)
		}
	}
	convertOneOfToAnyOf(schema.Items)
}
