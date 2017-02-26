package worker

import (
	"os"
	"time"

	"github.com/golang/glog"
)

func Run(allCnt, randCnt, allWorkers, maliciousWorkers, probability, threshold, conspirators int) {
	ret := SetWorkers(allWorkers, maliciousWorkers, probability, threshold, conspirators)
	if ret != maliciousWorkers {
		glog.Errorf("random malicious workers error")
		os.Exit(1)
	}
	dumpWorkers()
	taskFail = 0
	taskRight = 0
	taskConspirator = 0

	glog.Infof("begin %s times choose worker random\n", randCnt)
	randomRun(randCnt)
	//debug

	glog.Infof("begin %d times choose worker from trustGroup and untrustedGroup\n", allCnt-randCnt)
	subGroup()
	specificRunTimes := specificRun(allCnt-randCnt, randCnt)

	glog.Infof("specific run %d times, random run %d times, result is:", specificRunTimes, randCnt)
	dumpMalicioudWorkers()
}

func randomRun(k int) {
	for i := 0; i < k; i++ {
		w1, w2 := getRandomPair()
		glog.Infof("%d times to random select worker %d and %d to executor work\n", i, w1, w2)

		identical := executorTask(w1, w2)
		workers[w1].updateCredible(identical)
		workers[w2].updateCredible(identical)

		updateGraph(w1, w2, identical)
	}
}

func specificRun(k, randCnt int) int {
	for i := 0; i < k; i++ {
		if realtimeMaliciousNum <= 0 {
			glog.Infof("STOP: determine all worker is malicious, return")
			return i
		}

		w1, w2 := chooseWorkerFromSubGroup()
		glog.Infof("%d times to specific select worker %d and %d to executor work\n", i+randCnt, w1, w2)
		identical := executorTask(w1, w2)
		workers[w1].updateCredible(identical)
		workers[w2].updateCredible(identical)
		updateGraph(w1, w2, identical)

		detectMaliciousWorker()
	}
	return k
}

func getRandomPair() (int, int) {
	i := random.Intn(workerNum)
	var j int
	for {
		j = random.Intn(workerNum)

		if j != i {
			break
		}
	}

	return i, j
}

func executorTask(i, j int) bool {
	ret1 := workers[i].getResult()
	ret2 := workers[j].getResult()

	if ret1 == 1 && ret2 == 1 {
		taskRight++
		return true
	}

	if ret1 == 2 && ret2 == 2 {
		taskConspirator++
		return true
	}

	/*
		if ret1 == 2 && ret2 == 2 {
			return true
		}
	*/
	taskFail++
	return false
}

// depart group to trusted and untrusted
func subGroup() {
	unsortSeq := make([]int, workerNum)
	unsortVal := make([]int, workerNum)
	//unsortMap := make(map[int]int, workerNum)

	// idx equal
	idx := 0
	for i := 0; i < workerNum; i++ {
		if workers[i].isMalicious {
			continue
		}
		num := i
		val := workers[i].credible

		unsortSeq[idx] = num
		unsortVal[idx] = val
		idx++
	}

	realtimeWorkerNum = idx
	realtimeMaliciousNum = maliciousWorkerNum - (workerNum - idx)
	realtimeMaliciousNumForSubgroup = realtimeMaliciousNum
	//fmt.Printf("realtime WorkerNum %d, realtime MaliciousNum %d\n", idx, realtimeMaliciousNum)
	glog.Infof("realtime WorkerNum %d, realtime MaliciousNum %d\n", idx, realtimeMaliciousNum)
	if realtimeMaliciousNum <= 0 {
		//fmt.Printf("determine all worker is malicious, re-check parameters")
		glog.Infof("STOP: determine all worker is malicious, return")
		return
	}
	if realtimeMaliciousNum == 1 {
		realtimeMaliciousNumForSubgroup = 3
	}

	mySort(unsortSeq, unsortVal)

	glog.Infof("unsortSeq %v\n", unsortSeq)
	for i := 0; i < realtimeMaliciousNumForSubgroup; i++ {
		untrustedGroup[i] = unsortSeq[i]
	}
	for i, j := realtimeMaliciousNumForSubgroup, 0; i < realtimeWorkerNum; i++ {
		trustGroup[j] = unsortSeq[i]
		j++
	}
}

func detectMaliciousWorker() {
	needSubgroup1 := false
	needSubgroup2 := false

	for i := 0; i < workerNum; i++ {
		for j := 0; j < workerNum; j++ {
			if i == j {
				tmpGraph[i][j] = 0
			} else if workers[i].isMalicious || workers[j].isMalicious {
				tmpGraph[i][j] = 0
			} else if graph[i][j].weight == -1 || graph[i][j].weight == 100 {
				tmpGraph[i][j] = 1
			} else {
				tmpGraph[i][j] = 0
			}
		}
	}
	//dumpTmpGraph()

	for i := 0; i < workerNum; i++ {
		if workers[i].isMalicious {
			continue
		}
		ok := true
		for j := 0; j < workerNum; j++ {
			if tmpGraph[i][j] == 1 {
				ok = false
				break
			}
		}
		if ok {
			workers[i].isMalicious = true
			glog.Infof("FOUND: worker %d is malicious\n", i)
			needSubgroup1 = true
		}
	}

	// use b-k to detect malicious workers
	needSubgroup2 = doClique()

	if needSubgroup1 || needSubgroup2 {
		subGroup()
	}
}

// choose from untrustedGroup and trustGroup
func chooseWorkerFromSubGroup() (int, int) {
	var N1, N2 int
	var r1, r2 int
	var r, rr int
	r = random.Intn(realtimeMaliciousNumForSubgroup)
	r1 = untrustedGroup[r]
	glog.Infof("choose first worker %d from untrustedGroup\n", r1)

	fromZero := make([]int, 0)
	fromOne := make([]int, 0)

	//fmt.Printf("trustGroup len %d, %v\n", len(trustGroup), trustGroup)
	//fmt.Printf("untrustGroup len %d, %v\n", len(untrustedGroup), untrustedGroup)
	for i := 0; i < realtimeWorkerNum-realtimeMaliciousNumForSubgroup; i++ {
		j := trustGroup[i]
		if graph[r1][j].weight == -1 {
			fromZero = append(fromZero, j)
		} else if graph[r1][j].weight == 100 {
			fromOne = append(fromOne, j)
		}
	}

	glog.Infof("chooseWorkerFromSubGroup, trustGroup %v\n", trustGroup)
	glog.Infof("chooseWorkerFromSubGroup, fromZero %v\n", fromZero)
	glog.Infof("chooseWorkerFromSubGroup, fromOne %v\n", fromOne)
	N1 = len(fromZero)
	N2 = len(fromOne)
	if N1 != 0 {
		rr = random.Intn(N1)
		//fmt.Printf("fromZero %v, locate %d\n", N1, rr)
		//r2 = trustGroup[fromZero[rr]]
		r2 = fromZero[rr]
		glog.Infof("choose second worker %d from trustedGroup not work with first worker\n", r2)
	} else if N2 != 0 {
		rr = random.Intn(N2)
		//r2 = trustGroup[fromOne[rr]]
		r2 = fromOne[rr]
		glog.Infof("choose second worker %d from trustedGroup return right answer with first worker before\n", r2)
	} else {
		for {
			rr := random.Intn(realtimeMaliciousNumForSubgroup)
			if rr != r {
				r2 = untrustedGroup[rr]
				glog.Infof("choose second worker %d still from untrustedGroup\n", r2)
				break
			}
		}
	}

	return r1, r2
}

func resizeAllWorkers() {

}

func mySort(seq, val []int) {
	N := realtimeWorkerNum

	for i := 0; i < N; i++ {
		for j := N - 1; j > i; j-- {
			if val[j] < val[j-1] {
				val[j] ^= val[j-1]
				val[j-1] ^= val[j]
				val[j] ^= val[j-1]

				seq[j] ^= seq[j-1]
				seq[j-1] ^= seq[j]
				seq[j] ^= seq[j-1]
			}
		}
	}
	//fmt.Println("sorted seq ", seq)
	//fmt.Println("sorted val ", val)
}

func bk() {

}

func dumpMalicioudWorkers() {
	realMalicious := make([]int, 0)
	for i := 0; i < workerNum; i++ {
		if workers[i].cheat != 0 {
			realMalicious = append(realMalicious, i)
		}
	}
	glog.Infoln("real malicious workers is ", realMalicious)

	detectedMalicious := make([]int, 0)
	for i := 0; i < workerNum; i++ {
		if workers[i].isMalicious {
			detectedMalicious = append(detectedMalicious, i)
		}
	}
	glog.Infoln("detected malicious worker is ", detectedMalicious)
	glog.Infof("task fail times %d, task right times %d, task in conspirators times %d\n", taskFail, taskRight, taskConspirator)
}

func WaitGlogPrint() {
	select {
	case <-time.After(30 * time.Second):
	}
}
