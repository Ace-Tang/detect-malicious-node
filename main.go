package main

import (
	"flag"
	"hadoop/worker"
)

var (
	allWorkers       = flag.Int("all-workers", 10, "所有工作者数量")
	maliciousWorkers = flag.Int("malicious-workers", 2, "恶意工作者数量")
	cheatProbability = flag.Int("cheat-probility", 50, "作弊概率， 单位是%")
	taskallCnt       = flag.Int("task-all", 1000, "任务执行总次数")
	taskRandCnt      = flag.Int("task-rand", 200, "随机任务执行次数")
	maliThres        = flag.Int("mali-thres", 2, "bk 算法阀值")
)

func main() {
	flag.Parse()

	worker.Run(*taskallCnt, *taskRandCnt, *allWorkers, *maliciousWorkers, *cheatProbability, *maliThres)
}
