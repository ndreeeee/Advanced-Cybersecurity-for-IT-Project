package test
import rego.v1

url := "http://zta-trust-engine:8182/v1/context?user=alice"

resp := http.send({
		"method": "GET",
		"url": url,
	})
