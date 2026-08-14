(class_declaration
  name: (type_identifier) @name) @definition.class

(protocol_declaration
  name: (type_identifier) @name) @definition.class

(function_declaration
  name: (simple_identifier) @name) @definition.function

(call_expression
  (simple_identifier) @name) @reference.call

(call_expression
  (navigation_expression
    suffix: (navigation_suffix
      suffix: (simple_identifier) @name))) @reference.call
