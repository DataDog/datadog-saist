(struct_item
  name: (type_identifier) @name) @definition.class

(enum_item
  name: (type_identifier) @name) @definition.class

(union_item
  name: (type_identifier) @name) @definition.class

(trait_item
  name: (type_identifier) @name) @definition.class

(function_item
  name: (identifier) @name) @definition.function

(call_expression
  function: (identifier) @name) @reference.call

(call_expression
  function: (field_expression
    field: (field_identifier) @name)) @reference.call

(call_expression
  function: (scoped_identifier
    name: (identifier) @name)) @reference.call
