package worker

import "testing"

func TestFind(t *testing.T) {
	fa := []int{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
	}

	f := find(3)
	t.Log(f)
}
