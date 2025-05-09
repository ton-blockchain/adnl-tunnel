package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ActiveInboundSections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name:      "active_inbound_sections",
			Namespace: "tunnel",
			Help:      "Number of active incoming tunnel sections.",
		},
	)

	ActiveOutGateways = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "active_out_gateways",
			Namespace: "tunnel",
			Help:      "Number of active bind ports for outgoing and incoming traffic.",
		},
		[]string{"paid"},
	)

	ActiveRoutes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "active_routes",
			Namespace: "tunnel",
			Help:      "Number of active routes",
		},
		[]string{"paid"},
	)

	PacketsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "packets_counter",
			Namespace: "tunnel",
			Help:      "The number (thousands) of packets processed per second.",
		},
		[]string{"type"}, //  type (route/in/out)
	)

	PacketsPrepaidCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "packets_paid_counter",
			Namespace: "tunnel",
			Help:      "The number of packets paid, separated by tunnel type.",
		},
		[]string{"type"},
	)
)

var Registered = false

func RegisterMetrics() {
	if Registered {
		return
	}
	Registered = true

	prometheus.MustRegister(PacketsCounter)
	prometheus.MustRegister(PacketsPrepaidCounter)
	prometheus.MustRegister(ActiveInboundSections)
	prometheus.MustRegister(ActiveOutGateways)
	prometheus.MustRegister(ActiveRoutes)
}
