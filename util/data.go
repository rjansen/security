package util

import (
	"encoding/json"
	"io"
)

//JSONSerializable provides to a struct json external representation
type JSONSerializable interface {
	Marshal() ([]byte, error)
	//Marshal(writer io.Writer) error
	Unmarshal(reader io.Reader) error
}

//JSONObject adds support to marshall and unmarshall with JSON data type
type JSONObject struct {
}

//Marshal writes a json representation of Expansion
func (j *JSONObject) Marshal(object interface{}) ([]byte, error) {
	return json.Marshal(object)
}

//UnmarshalBytes reads a json representation into the provided struct
func (j *JSONObject) UnmarshalBytes(object interface{}, data []byte) error {
	return json.Unmarshal(data, &object)
}

// //Marshal reads a json representation of Expansion
// func (j *JSONObject) Marshal(writer io.Writer) error {
// 	return json.NewEncoder(writer).Encode(&j)
// }

//Unmarshal reads a json representation into the provided struct
func (j *JSONObject) Unmarshal(object interface{}, reader io.Reader) error {
	return json.NewDecoder(reader).Decode(&object)
}
