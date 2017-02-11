package worker

import (
	"fmt"
	"testing"
)

func TestSetWorkers(t *testing.T) {
	all := 20
	mali := 5
	fmt.Println("enter all workers %d, malicious %d", all, mali)

	cnt := SetWorkers(all, mali)
	if cnt != mali {
		t.Errorf("SetWorkers fail, get ret count %d\n", cnt)
	}
}
