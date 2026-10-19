package core

import "errors"

var (
	ErrNotFound       = errors.New("resource not found")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrForbidden      = errors.New("forbidden")
	ErrInvalidInput   = errors.New("invalid input")
	ErrTokenDisabled  = errors.New("token is disabled")
	ErrRateLimited    = errors.New("rate limit exceeded")
	ErrDuplicateToken = errors.New("token collision")
)
