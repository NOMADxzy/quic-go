package congestion

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/rpcClient"
)

const (
	// maxDatagramSize is the default maximum packet size used in the Linux TCP implementation.
	// Used in QUIC for congestion window computations in bytes.
	initialMaxDatagramSize     = protocol.ByteCount(protocol.InitialPacketSizeIPv4)
	maxBurstPackets            = 3
	renoBeta                   = 0.7 // Reno backoff factor.
	minCongestionWindowPackets = 2
	initialCongestionWindow    = 32
	ActionThreshold            = 0.1
)

type cubicSender struct {
	hybridSlowStart HybridSlowStart
	rttStats        *utils.RTTStats
	cubic           *Cubic
	pacer           *pacer
	clock           Clock

	rl        bool
	rlClient  rpcClient.AcerServiceClient
	preReward float32

	reno bool

	// Track the largest packet that has been sent.
	largestSentPacketNumber protocol.PacketNumber

	// Track the largest packet that has been acked.
	largestAckedPacketNumber protocol.PacketNumber

	// Track the largest packet number outstanding when a CWND cutback occurs.
	largestSentAtLastCutback protocol.PacketNumber

	// Whether the last loss event caused us to exit slowstart.
	// Used for stats collection of slowstartPacketsLost
	lastCutbackExitedSlowstart bool

	// Congestion window in bytes.
	congestionWindow protocol.ByteCount

	// Slow start congestion window in bytes, aka ssthresh.
	slowStartThreshold protocol.ByteCount

	// ACK counter for the Reno implementation.
	numAckedPackets uint64

	initialCongestionWindow    protocol.ByteCount
	initialMaxCongestionWindow protocol.ByteCount

	maxDatagramSize protocol.ByteCount

	lastState logging.CongestionState
	tracer    *logging.ConnectionTracer
}

var (
	_ SendAlgorithm               = &cubicSender{}
	_ SendAlgorithmWithDebugInfos = &cubicSender{}
)

// NewCubicSender makes a new cubic sender
func NewCubicSender(
	clock Clock,
	rttStats *utils.RTTStats,
	initialMaxDatagramSize protocol.ByteCount,
	reno bool,
	tracer *logging.ConnectionTracer,
) *cubicSender {
	return newCubicSender(
		clock,
		rttStats,
		reno,
		initialMaxDatagramSize,
		initialCongestionWindow*initialMaxDatagramSize,
		protocol.MaxCongestionWindowPackets*initialMaxDatagramSize,
		tracer,
	)
}

func newCubicSender(
	clock Clock,
	rttStats *utils.RTTStats,
	reno bool,
	initialMaxDatagramSize,
	initialCongestionWindow,
	initialMaxCongestionWindow protocol.ByteCount,
	tracer *logging.ConnectionTracer,
) *cubicSender {
	c := &cubicSender{
		rttStats:                   rttStats,
		rl:                         true,
		largestSentPacketNumber:    protocol.InvalidPacketNumber,
		largestAckedPacketNumber:   protocol.InvalidPacketNumber,
		largestSentAtLastCutback:   protocol.InvalidPacketNumber,
		initialCongestionWindow:    initialCongestionWindow,
		initialMaxCongestionWindow: initialMaxCongestionWindow,
		congestionWindow:           initialCongestionWindow,
		slowStartThreshold:         protocol.MaxByteCount,
		cubic:                      NewCubic(clock),
		clock:                      clock,
		reno:                       reno,
		tracer:                     tracer,
		maxDatagramSize:            initialMaxDatagramSize,
	}
	if c.rl {
		conn, err := grpc.Dial("[::]:50053", grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatal("连接失败", err)
		} else {
			// 创建客户端
			rlClient := rpcClient.NewAcerServiceClient(conn)
			c.rlClient = rlClient
		}
	}
	c.pacer = newPacer(c.BandwidthEstimate)
	if c.tracer != nil && c.tracer.UpdatedCongestionState != nil {
		c.lastState = logging.CongestionStateSlowStart
		c.tracer.UpdatedCongestionState(logging.CongestionStateSlowStart)
	}
	return c
}

// TimeUntilSend returns when the next packet should be sent.
func (c *cubicSender) TimeUntilSend(_ protocol.ByteCount) time.Time {
	return c.pacer.TimeUntilSend()
}

func (c *cubicSender) HasPacingBudget(now time.Time) bool {
	return c.pacer.Budget(now) >= c.maxDatagramSize
}

func (c *cubicSender) maxCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * protocol.MaxCongestionWindowPackets
}

func (c *cubicSender) minCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * minCongestionWindowPackets
}

func (c *cubicSender) OnPacketSent(
	sentTime time.Time,
	_ protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	c.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}
	c.largestSentPacketNumber = packetNumber
	c.hybridSlowStart.OnPacketSent(packetNumber)
}

func (c *cubicSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < c.GetCongestionWindow()
}

func (c *cubicSender) InRecovery() bool {
	return c.largestAckedPacketNumber != protocol.InvalidPacketNumber && c.largestAckedPacketNumber <= c.largestSentAtLastCutback
}

func (c *cubicSender) InSlowStart() bool {
	return c.GetCongestionWindow() < c.slowStartThreshold
}

func (c *cubicSender) GetCongestionWindow() protocol.ByteCount {
	return c.congestionWindow
}

func (c *cubicSender) MaybeExitSlowStart() {
	if c.InSlowStart() &&
		c.hybridSlowStart.ShouldExitSlowStart(c.rttStats.LatestRTT(), c.rttStats.MinRTT(), c.GetCongestionWindow()/c.maxDatagramSize) {
		// exit slow start
		c.slowStartThreshold = c.congestionWindow
		c.maybeTraceStateChange(logging.CongestionStateCongestionAvoidance)
	}
}

func (c *cubicSender) OnPacketAcked(
	ackedPacketNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime time.Time,
	metrics *utils.Metrics,
) {
	c.largestAckedPacketNumber = utils.Max(ackedPacketNumber, c.largestAckedPacketNumber)
	if c.InRecovery() {
		return
	}
	//if metrics.ShouldReset() {
	//	//dura := time.Now().Sub(metrics.StartTime)
	//
	//	//Reward := int64(10 * throughput / initialMaxDatagramSize) - int64(c.rttStats.SmoothedRTT() / time.Second) - int64(2000 * LossRate)
	//	//fmt.Println("r1:", r1, "r2:", r2, "r3:", r3)
	//}

	if c.rl {
		if !metrics.ShouldReset() {
			return
		}
		sendRate := metrics.Sent
		//sendBytes := metrics.SentBytes
		LossRate := float64(metrics.Lost) / float64(metrics.Sent)
		AckRate := float64(metrics.Acked) / float64(metrics.Sent)
		bestRTT := c.rttStats.BestRTT()
		avgLatency := float32(c.rttStats.SmoothedRTT() / time.Millisecond)
		throughput := metrics.SentBytes
		fmt.Println("sendRate:", sendRate, "LossRate:", LossRate, "AckRate:", AckRate, "avgLatency:", avgLatency, "bestRTT:", bestRTT,
			"throughput:", throughput, "congestionWindow:", c.congestionWindow, "priorInFlight", priorInFlight)
		r1 := float32(throughput) / float32(initialMaxDatagramSize) / 10
		r2 := -float32(c.rttStats.SmoothedRTT() / 10 / time.Millisecond)
		r3 := -float32(LossRate)
		r4 := -float32(c.congestionWindow-priorInFlight-maxBurstPackets*c.maxDatagramSize) / float32(initialMaxDatagramSize) / 100
		s4 := -r4
		if c.congestionWindow-priorInFlight-maxBurstPackets*c.maxDatagramSize < 0 {
			r4 = -10
		}
		//s1 := float32(sendBytes / initialMaxDatagramSize)
		//s2 := float32(priorInFlight / initialMaxDatagramSize)
		//s3 := 100 * avgLatency
		//s4 := float32(c.congestionWindow / initialMaxDatagramSize)
		fmt.Println("r1:", r1, "r2:", r2, "r3:", r3, "r4:", r4)
		reward := r1 + r4 + c.preReward
		resp, err := c.rlClient.GetExplorationAction(context.Background(), &rpcClient.StateReward{State: []float32{s4},
			Reward: reward})
		_, err = c.rlClient.UpdateMetric(context.Background(), &rpcClient.Metric{Metrics: []float32{reward, avgLatency, float32(throughput / c.maxDatagramSize)}})
		c.preReward = 0

		//if lostCnt > 0 {
		//	fmt.Println("发生丢包，数量:", lostCnt)
		//}
		if err == nil {
			act := float32(resp.Action-resp.ActionDim) / float32(resp.ActionDim)
			if resp.Action >= -1 {

				preCwnd := c.congestionWindow
				if act >= 0 {
					if c.congestionWindow == c.maxCongestionWindow() {
						c.preReward = -5
					} else {
						c.congestionWindow = protocol.ByteCount(float64(c.congestionWindow) * float64(1+act))
					}
				} else {
					if c.congestionWindow == minCongestionWindowPackets*initialMaxDatagramSize {
						c.preReward = -5
					} else {
						c.congestionWindow = minCongestionWindowPackets*initialMaxDatagramSize + protocol.ByteCount(float64(c.congestionWindow-minCongestionWindowPackets*initialMaxDatagramSize)*float64(1+act))
					}
				}
				c.congestionWindow = utils.Min(c.congestionWindow, c.maxCongestionWindow())
				log.Printf("action : %f, increase cwnd from %d to %d \n", act, preCwnd, c.congestionWindow)
			} else {
				fmt.Printf("rl action error, action: %f\n", resp.Action)
			}

			return
		}
		log.Fatal("GRPC method error", err)
	} else {
		preCwnd := c.congestionWindow
		LossRate := float64(metrics.Lost) / float64(metrics.Sent)

		c.maybeIncreaseCwnd(ackedPacketNumber, ackedBytes, priorInFlight, eventTime)
		r1 := float32(metrics.SentBytes / initialMaxDatagramSize)
		r2 := -float32(c.rttStats.SmoothedRTT() / 10 / time.Millisecond)
		r3 := -float32(2000 * LossRate)
		r4 := -float32((c.congestionWindow - priorInFlight - maxBurstPackets*c.maxDatagramSize) / 10 / initialMaxDatagramSize)

		fmt.Println("r1:", r1, "r2:", r2, "r3:", r3, "r4:", r4)
		fmt.Printf("(origin Algo)increase cwnd from %d to %d \n", preCwnd, c.congestionWindow)
	}
	if c.InSlowStart() {
		c.hybridSlowStart.OnPacketAcked(ackedPacketNumber)
	}
}

func (c *cubicSender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes, priorInFlight protocol.ByteCount) {
	// TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
	// already sent should be treated as a single loss event, since it's expected.
	if packetNumber <= c.largestSentAtLastCutback {
		return
	}
	c.lastCutbackExitedSlowstart = c.InSlowStart()
	c.maybeTraceStateChange(logging.CongestionStateRecovery)

	if c.reno {
		c.congestionWindow = protocol.ByteCount(float64(c.congestionWindow) * renoBeta)
	} else {
		c.congestionWindow = c.cubic.CongestionWindowAfterPacketLoss(c.congestionWindow)
	}
	if minCwnd := c.minCongestionWindow(); c.congestionWindow < minCwnd {
		c.congestionWindow = minCwnd
	}
	c.slowStartThreshold = c.congestionWindow
	c.largestSentAtLastCutback = c.largestSentPacketNumber
	// reset packet count from congestion avoidance mode. We start
	// counting again when we're out of recovery.
	c.numAckedPackets = 0
}

// Called when we receive an ack. Normal TCP tracks how many packets one ack
// represents, but quic has a separate ack for each packet.
func (c *cubicSender) maybeIncreaseCwnd(
	_ protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime time.Time,
) {
	// Do not increase the congestion window unless the sender is close to using
	// the current window.
	if !c.isCwndLimited(priorInFlight) {
		c.cubic.OnApplicationLimited()
		c.maybeTraceStateChange(logging.CongestionStateApplicationLimited)
		return
	}

	if c.congestionWindow >= c.maxCongestionWindow() {
		return
	}
	if c.InSlowStart() {
		// TCP slow start, exponential growth, increase by one for each ACK.
		c.congestionWindow += c.maxDatagramSize
		c.maybeTraceStateChange(logging.CongestionStateSlowStart)
		return
	}
	// Congestion avoidance
	c.maybeTraceStateChange(logging.CongestionStateCongestionAvoidance)
	if c.reno {
		// Classic Reno congestion avoidance.
		c.numAckedPackets++
		if c.numAckedPackets >= uint64(c.congestionWindow/c.maxDatagramSize) {
			c.congestionWindow += c.maxDatagramSize
			c.numAckedPackets = 0
		}
	} else {
		c.congestionWindow = utils.Min(c.maxCongestionWindow(), c.cubic.CongestionWindowAfterAck(ackedBytes, c.congestionWindow, c.rttStats.MinRTT(), eventTime))
	}
}

func (c *cubicSender) isCwndLimited(bytesInFlight protocol.ByteCount) bool {
	congestionWindow := c.GetCongestionWindow()
	//fmt.Println("bytesInFlight:", bytesInFlight, "congestionWindow:", congestionWindow)
	if bytesInFlight >= congestionWindow {
		return true
	}
	availableBytes := congestionWindow - bytesInFlight
	slowStartLimited := c.InSlowStart() && bytesInFlight > congestionWindow/2
	return slowStartLimited || availableBytes <= maxBurstPackets*c.maxDatagramSize
}

// BandwidthEstimate returns the current bandwidth estimate
func (c *cubicSender) BandwidthEstimate() Bandwidth {
	srtt := c.rttStats.SmoothedRTT()
	if srtt == 0 {
		// If we haven't measured an rtt, the bandwidth estimate is unknown.
		return infBandwidth
	}
	return BandwidthFromDelta(c.GetCongestionWindow(), srtt)
}

// OnRetransmissionTimeout is called on an retransmission timeout
func (c *cubicSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
	if !packetsRetransmitted {
		return
	}
	c.hybridSlowStart.Restart()
	c.cubic.Reset()
	c.slowStartThreshold = c.congestionWindow / 2
	c.congestionWindow = c.minCongestionWindow()
}

// OnConnectionMigration is called when the connection is migrated (?)
func (c *cubicSender) OnConnectionMigration() {
	c.hybridSlowStart.Restart()
	c.largestSentPacketNumber = protocol.InvalidPacketNumber
	c.largestAckedPacketNumber = protocol.InvalidPacketNumber
	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
	c.lastCutbackExitedSlowstart = false
	c.cubic.Reset()
	c.numAckedPackets = 0
	c.congestionWindow = c.initialCongestionWindow
	c.slowStartThreshold = c.initialMaxCongestionWindow
}

func (c *cubicSender) maybeTraceStateChange(new logging.CongestionState) {
	if c.tracer == nil || c.tracer.UpdatedCongestionState == nil || new == c.lastState {
		return
	}
	c.tracer.UpdatedCongestionState(new)
	c.lastState = new
}

func (c *cubicSender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < c.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", c.maxDatagramSize, s))
	}
	cwndIsMinCwnd := c.congestionWindow == c.minCongestionWindow()
	c.maxDatagramSize = s
	if cwndIsMinCwnd {
		c.congestionWindow = c.minCongestionWindow()
	}
	c.pacer.SetMaxDatagramSize(s)
}
