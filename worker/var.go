package worker

import "math/rand"

//Worker , cheat means cheat probability, unit is %, credible initial 1
type Worker struct {
	seq      int
	cheat    int
	credible int

	completedTask int
	goodTask      int

	isMalicious bool
}

type Graph struct {
	goodTask int
	allTask  int
	weight   int // unit is %, initial -1
}

var (
	workerNum          int
	maliciousWorkerNum int
	workers            []*Worker
	//workers     = make(map[int]int) // map[worker][whether is malicious worker], 0 means normal, cheat probability means malicious
	//credible    = make(map[int]int) // initial is 100 , unit is %

	graph [][]Graph // graph for b-k algorithm, Wi,j = wj,i

	//workerGraph   [1000][1000]int
	//graphGoodTask [1000][1000]int // graph for b-k algorithm
	//graphAllTask  [1000][1000]int // graph for b-k algorithm

	random *rand.Rand

	trustGroup           []int
	untrustedGroup       []int
	realtimeWorkerNum    int // realtime all worker quanity after deleted
	realtimeMaliciousNum int // realtime malicious worker quanity after deleted
)