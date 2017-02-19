package main

import (
	"flag"
	"hadoop/worker"
)

var (
	allWorkers       = flag.Int("all-workers", 50, "all workers")
	maliciousWorkers = flag.Int("malicious-workers", 10, "malicious workers")
	cheatProbability = flag.Int("cheat-probility", 50, "cheat probility, unit is %")
	taskallCnt       = flag.Int("task-all", 100, "task run all times")
	taskRandCnt      = flag.Int("task-rand", 20, "random select workers times")
	maliThres        = flag.Int("mali-thres", 10, "bk algorithm threshold for delete malicious worker")
)

func main() {
	flag.Parse()

	worker.Run(*taskallCnt, *taskRandCnt, *allWorkers, *maliciousWorkers, *cheatProbability, *maliThres)
}
