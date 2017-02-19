package worker

import "fmt"

func union(p, q int) {
	l := find(p)
	r := find(q)

	if l != r {
		if tmpGraph[l][r] == 1 {
			fa[r] = l
			sz[r]++
		}
	}
}

func find(p int) int {
	if fa[p] == p {
		return p
	}
	return find(fa[p])
}

func detect() bool {
	flag := false
	for i := 0; i < workerNum; i++ {
		if fa[i] == -1 {
			continue
		}
		f := find(i)
		if sz[f] < maliThres {
			workers[i].isMalicious = true
			fmt.Printf("worker %d is malicious", i)
			flag = true
		}
	}
	return flag
}

func initUnionV() {
	for i := 0; i < workerNum; i++ {
		sz[i] = 1
		if workers[i].isMalicious {
			fa[i] = -1
		} else {
			fa[i] = i
		}
	}
}

func doClique() bool {
	initUnionV()
	for i := 0; i < workerNum; i++ {
		for j := 0; j < workerNum; j++ {
			if fa[i] == -1 || fa[j] == -1 {
				continue
			}
			union(i, j)
		}
	}
	dumpTmpGraph()

	return detect()
}
