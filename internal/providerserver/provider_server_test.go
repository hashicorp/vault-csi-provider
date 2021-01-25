package providerserver

import (
	"testing"
)

func TestUnmarshalParameters(t *testing.T) {
	// var parameters config.Parameters
	// var m map[string]interface{}
	// parametersStr, err := ioutil.ReadFile("testdata/example-parameters-string.txt")
	// require.NoError(t, err)
	// y, err := yaml.JSONToYAML([]byte(parametersStr))
	// require.NoError(t, err)
	// _, _ = fmt.Println(string(y))
	// err = yaml3.Unmarshal(y, &parameters)
	// t.Logf("%+v", parameters)
	// require.NoError(t, err)
	// t.Fatal()
	// err = json.Unmarshal([]byte(parametersStr), &m)
	// require.NoError(t, err)
	// decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
	// 	Result:           &parameters,
	// 	WeaklyTypedInput: true,
	// 	TagName:          "yaml",
	// })
	// require.NoError(t, err)
	// t.Log(m)
	// t.Log(reflect.TypeOf(m["roleName"]))
	// t.Log(reflect.TypeOf(m["vaultSkipTLSVerify"]))
	// t.Log(reflect.TypeOf(m["objects"]))
	// err = decoder.Decode(m)
	// require.NoError(t, err)
	// assert.Equal(t, "example-role", parameters.VaultRoleName)
	// assert.Equal(t, "http://vault:8200", parameters.VaultAddress)
}
