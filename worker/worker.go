package worker

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/golang/glog"
)

// SetWorkers all -> all workers, malicious -> malicious workers
func SetWorkers(all, malicious, probability, thres, conspirators int) int {
	// using shuffle algorithm
	workerNum = all
	maliciousWorkerNum = malicious
	conspiratorWorkerNum = conspirators
	maliThres = thres
	workers = make([]*Worker, all)
	random = rand.New(rand.NewSource(time.Now().Unix()))
	graph = make([][]Graph, all)
	tmpGraph = make([][]int, all)
	for i := 0; i < all; i++ {
		tmp := make([]Graph, all)
		graph[i] = tmp

		tmpp := make([]int, all)
		tmpGraph[i] = tmpp
	}
	for i := 0; i < all; i++ {
		for j := 0; j < all; j++ {
			graph[i][j].weight = -1
		}
	}
	fa = make([]int, all)
	sz = make([]int, all)
	trustGroup = make([]int, workerNum-maliciousWorkerNum)
	untrustedGroup = make([]int, maliciousWorkerNum+2)

	var front, last int
	var sortedArr [1000]int

	for i := 0; i < all; i++ {
		workers[i] = new(Worker)
		workers[i].credible = 100
		workers[i].seq = i
		sortedArr[i] = i
	}

	for i := 0; i < all; i++ {
		front = random.Intn(all)
		last = random.Intn(all)
		if front != last {
			sortedArr[last] ^= sortedArr[front]
			sortedArr[front] ^= sortedArr[last]
			sortedArr[last] ^= sortedArr[front]
		}
	}

	maliciousWorkers, conspiratorsWorkers := []int{}, []int{}
	for j := 0; j < conspirators; j++ {
		maliciousLocate := sortedArr[j]
		conspiratorsWorkers = append(conspiratorsWorkers, maliciousLocate)
		maliciousWorkers = append(maliciousWorkers, maliciousLocate)
		workers[maliciousLocate].cheat = probability
		workers[maliciousLocate].isConspirator = true
	}

	for i := conspirators; i < malicious; i++ {
		maliciousLocate := sortedArr[i]
		maliciousWorkers = append(maliciousWorkers, maliciousLocate)
		workers[maliciousLocate].cheat = probability
	}

	glog.Infof("get all %d workers, malicious workers is %v, conspirator workers is %v\n", all, maliciousWorkers, conspiratorsWorkers)
	//fmt.Printf("get all %d workers, malicious workers is %v\n", all, maliciousWorkers)

	return len(maliciousWorkers)
}

func initialWorkersInfo() {

}

/*
func updateCredible(seq, val int) {
	workers[seq].credible = val
}
*/

func (w *Worker) updateCredible(ok bool) {
	if ok {
		w.goodTask++
	}
	w.completedTask++
	w.credible = int(float32(w.goodTask) / float32(w.completedTask) * 100)
}

func (w *Worker) beCheat() bool {
	p := random.Intn(100)
	if p >= w.cheat {
		return false
	}
	return true
}

// return 1 means right result, 0 means wrong, 2 means conspirators
func (w *Worker) getResult() int {
	if w.cheat != 0 {
		p := random.Intn(100)
		if p < w.cheat {
			if w.isConspirator {
				return 2
			} else {
				return 0
			}
		}
	}

	return 1
}

func updateGraph(i, j int, ok bool) {
	if ok {
		graph[i][j].goodTask++
	}
	graph[i][j].allTask++

	graph[i][j].weight = int(float32(graph[i][j].goodTask) / float32(graph[i][j].allTask) * 100)

	graph[j][i] = graph[i][j]
}

func dumpGraph() {
	fmt.Printf("graph %+v\n", graph)
}

func dumpTmpGraph() {
	fmt.Printf("tmpgraph %+v\n", tmpGraph)
}

func dumpWorkers() {
	glog.Infoln("show all workers")
	for i := 0; i < workerNum; i++ {
		glog.Infof("worker %d, value %+v\n", i, workers[i])
	}
}
