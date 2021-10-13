package utilx

func NewAPIError(errCode int, err error) *HTTPError {
	er := &HTTPError{
		ErrCode: errCode,
	}
	if err != nil {
		er.Message = err.Error()
	}
	return er
}

func NewAPIData(data interface{}) *HTTPError {
	return &HTTPError{
		Data: data,
	}
}

// HTTPError example
type HTTPError struct {
	ErrCode int         `json:"c" example:"1001"`
	Message string      `json:"m,omitempty" example:"error"`
	Data    interface{} `json:"d,omitempty"`
}
