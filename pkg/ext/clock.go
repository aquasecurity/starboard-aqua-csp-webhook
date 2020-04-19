package ext

import "time"

var (
	SystemClock = &systemClock{}
)

type Clock interface {
	Now() time.Time
}

type systemClock struct {
}

func (sc *systemClock) Now() time.Time {
	return time.Now()
}

type fixedClock struct {
	time time.Time
}

func (fc *fixedClock) Now() time.Time {
	return fc.time
}

func NewFixedClock(time time.Time) Clock {
	return &fixedClock{
		time: time,
	}
}
