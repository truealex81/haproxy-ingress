/*
Copyright 2019 The HAProxy Ingress Controller Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"
)

// FullQualifiedName ...
func FullQualifiedName(namespace, name string) string {
	// TODO cross namespace
	return fmt.Sprintf("%s/%s", namespace, name)
}

// GCD calculates the Greatest Common Divisor between a and b
func GCD(a, b int) int {
	for b != 0 {
		r := a % b
		a, b = b, r
	}
	return a
}

// LCM calculates the Least Common Multiple between a and b
func LCM(a, b int) int {
	return a * (b / GCD(a, b))
}
