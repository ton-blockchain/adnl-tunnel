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

	PacketsPerSecond = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "packets_per_second",
			Namespace: "tunnel",
			Help:      "The number of packets processed per second for each tunnel.",
		},
		[]string{"tunnel_id", "type", "paid"}, // tunnel id and type (route/in/out)
	)

	PacketsPrepaid = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "packets_paid",
			Namespace: "tunnel",
			Help:      "The number of packets paid, separated by tunnel type.",
		},
		[]string{"tunnel_id", "type"},
	)
)

var Registered = false

func RegisterMetrics() {
	if Registered {
		return
	}
	Registered = true
	
	prometheus.MustRegister(PacketsPerSecond)
	prometheus.MustRegister(PacketsPrepaid)
	prometheus.MustRegister(ActiveInboundSections)
	prometheus.MustRegister(ActiveOutGateways)
	prometheus.MustRegister(ActiveRoutes)
}
