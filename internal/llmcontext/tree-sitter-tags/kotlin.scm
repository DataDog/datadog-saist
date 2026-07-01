(class_declaration
  name: (identifier) @name) @definition.class

(object_declaration
  name: (identifier) @name) @definition.class

(companion_object
  name: (identifier) @name) @definition.class

(function_declaration
  name: (identifier) @name) @definition.function

(call_expression
  (identifier) @name) @reference.call

(call_expression
  (navigation_expression
    (identifier) @name .)) @reference.call

(constructor_invocation
  (user_type
    (identifier) @name)) @reference.class
