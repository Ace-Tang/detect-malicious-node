package worker

import "github.com/golang/glog"

func union(p, q int) {
	l := find(p)
	r := find(q)
	//	fmt.Printf("%v\n", fa)

	//	fmt.Printf("p = %d, q = %d, tmpGraph %d\n", p, q, tmpGraph[p][q])
	if l != r {
		if tmpGraph[l][r] == 1 {
			//			fmt.Printf("after tmpGraph %v\n", fa)
			fa[r] = l
			sz[l]++
		}
	}
}

func find(p int) int {
	//fmt.Printf("p = %d, fa[p]= %d\n", p, fa[p])
	if fa[p] == p {
		//fmt.Printf("fa[p] %d\n", fa[p])
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
		//fmt.Printf("worker %d, father %d, size %d\n", i, f, sz[f])
		if sz[f] < maliThres {
			workers[i].isMalicious = true
			glog.Infof("FOUND: worker %d is malicious\n", i)
			//fmt.Printf("worker %d is malicious\n", i)
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
	//dumpTmpGraph()

	return detect()
}
