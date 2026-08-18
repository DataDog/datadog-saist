(class_definition
  name: (identifier) @name) @definition.class

(mixin_declaration
  name: (identifier) @name) @definition.class

(enum_declaration
  name: (identifier) @name) @definition.class

(extension_declaration
  name: (identifier) @name) @definition.class

(function_signature
  name: (identifier) @name) @definition.function

(constructor_signature
  name: (identifier) @name) @definition.function

(
  (identifier) @name
  .
  (selector
    (argument_part))
) @reference.call

(
  (_)
  .
  (selector
    [
      (unconditional_assignable_selector
        (identifier) @name)
      (conditional_assignable_selector
        (identifier) @name)
    ])
  .
  (selector
    (argument_part))
) @reference.call
