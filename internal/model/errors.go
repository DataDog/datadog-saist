package model

import "errors"

var ErrInvalidLanguage = errors.New("invalid language")
var ErrCannotGetContext = errors.New("cannot get context")
var ErrUnsupportedModel = errors.New("unsupported model")
var ErrUserTemplateNotFound = errors.New("user template not found")
var ErrSystemTemplateNotFound = errors.New("system template not found")

var ErrTemplateExecution = errors.New("template failed to build")
var ErrLLMCall = errors.New("LLM call failed")
var ErrGettingTags = errors.New("get tags failed")
