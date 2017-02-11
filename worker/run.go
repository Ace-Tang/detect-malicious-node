package worker

import (
	"fmt"
	"os"

	"github.com/golang/glog"
)

func Run(allCnt, randCnt, allWorkers, maliciousWorkers, probability int) {
	ret := SetWorkers(allWorkers, maliciousWorkers, probability)
	if ret != maliciousWorkers {
		glog.Errorf("random malicious workers error")
		os.Exit(1)
	}

	randomRun(randCnt)
	specificRun(allCnt - randCnt)
}

func randomRun(k int) {
	for i := 0; i < k; i++ {
		w1, w2 := getRandomPair()
		glog.Infof("random select worker %d and %d to executor work\n", w1, w2)

		identical := executorTask(w1, w2)
		workers[w1].updateCredible(identical)
		workers[w2].updateCredible(identical)

		updateGraph(w1, w2, identical)
	}
}

func specificRun(k int) {
	for i := 0; i < k; i++ {
		w1, w2 := chooseWorkerFromSubGroup()
		identical := executorTask(w1, w2)
		workers[w1].updateCredible(identical)
		workers[w2].updateCredible(identical)
		updateGraph(w1, w2, identical)

		detectMaliciousWorker()
	}
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

	return (ret1 == ret2)
}

// depart group to trusted and untrusted
func subGroup() {
	unsortSeq := make([]int, workerNum)
	unsortVal := make([]int, workerNum)
	//unsortMap := make(map[int]int, workerNum)

	// first sort
	for i := 0; i < workerNum; i++ {
		if workers[i].isMalicious {
			continue
		}
		num := i
		val := workers[i].credible

		unsortSeq[i] = num
		unsortVal[i] = val

		//unsortMap[num] = val
	}

	mySort(unsortSeq, unsortVal)

	for i := 0; i < realtimeMaliciousNum; i++ {
		untrustedGroup[i] = unsortSeq[i]
	}
	for i := realtimeMaliciousNum; i < realtimeWorkerNum; i++ {
		trustGroup[i] = unsortSeq[i]
	}
}

func detectMaliciousWorker() {

}

// choose from untrustedGroup and trustGroup
func chooseWorkerFromSubGroup() (int, int) {
	var N1, N2 int
	var r1, r2 int
	r := random.Intn(maliciousWorkerNum)
	r1 = untrustedGroup[r]

	fromZero := make([]int, workerNum)
	fromOne := make([]int, workerNum)

	for _, j := range trustGroup {
		if graph[r1][j].weight == -1 {
			fromZero = append(fromZero, j)
		} else if graph[r1][j].weight == 100 {
			fromOne = append(fromOne, j)
		}
	}

	N1 = len(fromZero)
	if N1 != 0 {
		r2 = random.Intn(N1)
	} else if N2 != 0 {
		r2 = random.Intn(N2)
	} else {
		for {
			rr := random.Intn(maliciousWorkerNum)
			if rr != r {
				r2 = untrustedGroup[rr]
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
	fmt.Printf("sorted seq ", seq)
	fmt.Printf("sorted val ", val)
}

func bk() {

}
