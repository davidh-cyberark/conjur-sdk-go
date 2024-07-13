package conjur

import "math/rand"

func RandSeq(charlist []rune, numchars int) string {
	b := make([]rune, numchars)
	for i := range b {
		b[i] = charlist[rand.Intn(len(charlist))]
	}
	return string(b)
}
