(class_declaration
  name: (name) @name) @definition.class

(interface_declaration
  name: (name) @name) @definition.class

(trait_declaration
  name: (name) @name) @definition.class

(function_definition
  name: (name) @name) @definition.function

(method_declaration
  name: (name) @name) @definition.function

(function_call_expression
  function: (name) @name) @reference.call

(member_call_expression
  name: (name) @name) @reference.call

(scoped_call_expression
  name: (name) @name) @reference.call
