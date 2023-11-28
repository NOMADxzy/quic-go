package utils

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"time"
)

type Metrics struct {
	interval  time.Duration
	StartTime time.Time
	Acked     int64
	Sent      int64
	Lost      int64
	SentBytes protocol.ByteCount
	LostBytes protocol.ByteCount
}

func NewMetrics(itl time.Duration) *Metrics {
	return &Metrics{
		interval:  itl,
		StartTime: time.Now(),
		SentBytes: 0,
		LostBytes: 0,
	}
}

func (m *Metrics) ShouldReset() bool {
	return time.Now().Sub(m.StartTime) > m.interval
}

func (m *Metrics) OnLost(lostBytes protocol.ByteCount, lostCnt int) {
	m.Lost += int64(lostCnt)
	m.LostBytes += lostBytes
}

func (m *Metrics) OnAck() {
	m.Acked++
}

func (m *Metrics) Reset() {
	m.StartTime = time.Now()
	m.SentBytes = 0
	m.LostBytes = 0
	m.Acked = 0
	m.Sent = 0
	m.Lost = 0
}
