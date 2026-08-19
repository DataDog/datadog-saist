(struct_specifier
  name: (type_identifier) @name) @definition.class

(class_specifier
  name: (type_identifier) @name) @definition.class

(union_specifier
  name: (type_identifier) @name) @definition.class

(enum_specifier
  name: (type_identifier) @name) @definition.type

(function_declarator
  declarator: (identifier) @name) @definition.function

(function_declarator
  declarator: (field_identifier) @name) @definition.function

(function_declarator
  declarator: (qualified_identifier
    name: (identifier) @name)) @definition.method

(call_expression
  function: (identifier) @name) @reference.call

(call_expression
  function: (field_expression
    field: (field_identifier) @name)) @reference.call

(call_expression
  function: (qualified_identifier
    name: (identifier) @name)) @reference.call
