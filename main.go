package main

import (
	"flag"
	"hadoop/worker"
)

var (
	allWorkers       = flag.Int("all-workers", 10, "all workers")
	maliciousWorkers = flag.Int("malicious-workers", 2, "malicious workers")
	cheatProbability = flag.Int("cheat-probility", 50, "cheat probility, unit is %")
	taskallCnt       = flag.Int("task-all", 1000, "task run all times")
	taskRandCnt      = flag.Int("task-rand", 200, "random select workers times")
	maliThres        = flag.Int("mali-thres", 2, "bk algorithm threshold for delete malicious worker")
)

func main() {
	flag.Parse()

	worker.Run(*taskallCnt, *taskRandCnt, *allWorkers, *maliciousWorkers, *cheatProbability, *maliThres)
}
