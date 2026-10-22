package scout

import (
	"encoding/json"
	"fmt"
	"os"
)

// SelectedConfig changes only one endpoint field in a copy. Unknown fields and
// all registration credentials, including the original peer pin, are retained.
// The selected port/SNI/transport must still be passed as command-line flags.
func SelectedConfig(original []byte, target Target) ([]byte, error) {
	if !target.Endpoint.IsValid() {
		return nil, fmt.Errorf("invalid selected endpoint")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(original, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, fmt.Errorf("configuration must be a JSON object")
	}
	var field string
	switch target.Transport {
	case QUIC:
		field = "endpoint_v4"
	case HTTP2:
		field = "endpoint_h2_v4"
	default:
		return nil, fmt.Errorf("invalid selected transport")
	}
	if target.Endpoint.Addr().Is6() {
		field = field[:len(field)-1] + "6"
	}
	fields[field], _ = json.Marshal(target.Endpoint.Addr().String())
	body, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// WriteNewFile refuses existing files and symlinks, including dangling ones.
// A partially written new file is removed on failure. It never calls SaveConfig,
// which permits overwriting and is inappropriate for a scanner's optional copy.
func WriteNewFile(path string, body []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
