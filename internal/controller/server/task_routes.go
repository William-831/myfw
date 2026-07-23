package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/stream"
)

// registerTaskRoutes mounts M5's minimal apply endpoint. Full state-machine
// endpoints (approvals, snapshot lookup) land in M7.
func registerTaskRoutes(r gin.IRouter, s *stream.Service) {
	g := r.Group("/api/v1")
	g.POST("/nodes/:id/apply", func(c *gin.Context) { applyNow(c, s) })
	g.GET("/nodes/connected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"nodes": s.Reg.Connected()})
	})
}

// applyReq is the tiny wire form of an ad-hoc Apply. Every rule is passed as a
// map that we translate into a CompiledRule. This is intentionally not the
// full Policy model — that's M6.
type applyReq struct {
	Rules []struct {
		ID          string `json:"id"`
		Direction   string `json:"direction"`
		Source      string `json:"source"`
		Destination string `json:"destination"`
		Protocol    string `json:"protocol"`
		PortRange   string `json:"port_range"`
		Action      string `json:"action"`
		Mark        uint32 `json:"mark"`
		NatTo       string `json:"nat_to"`
		Priority    int32  `json:"priority"`
	} `json:"rules"`
	ConfirmDeadlineSeconds int64 `json:"confirm_deadline_seconds"`
}

func applyNow(c *gin.Context, s *stream.Service) {
	id := c.Param("id")
	var body applyReq
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rules := make([]*myfwv1.CompiledRule, 0, len(body.Rules))
	for _, r := range body.Rules {
		cr, err := compileWireRule(r.ID, r.Direction, r.Source, r.Destination, r.Protocol, r.PortRange, r.Action, r.Mark, r.NatTo, r.Priority)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		rules = append(rules, cr)
	}

	taskID := "t_" + uuid.NewString()
	deadline := time.Now().Add(defaultConfirmDeadline(body.ConfirmDeadlineSeconds))

	// Subscribe BEFORE Send so we don't miss a fast result.
	resultsCh, unsub := s.SubscribeTaskResults()
	defer unsub()

	msg := &myfwv1.ControllerToAgent{
		Payload: &myfwv1.ControllerToAgent_Apply{
			Apply: &myfwv1.ApplyTask{
				TaskId: taskID,
				RuleSet: &myfwv1.RuleSet{
					NodeId:  id,
					Version: time.Now().Unix(),
					Rules:   rules,
				},
				ConfirmDeadlineUnix: deadline.Unix(),
			},
		},
	}

	if err := s.Reg.Send(id, msg); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	// Wait for THIS specific task_id, ignoring other results that arrive.
	deadlineCtx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	for {
		select {
		case res, ok := <-resultsCh:
			if !ok {
				c.JSON(http.StatusAccepted, gin.H{"task_id": taskID, "warning": "subscription closed"})
				return
			}
			if res.TaskId != taskID {
				continue
			}
			status := http.StatusOK
			if !res.Ok {
				status = http.StatusInternalServerError
			}
			c.JSON(status, gin.H{
				"task_id":     taskID,
				"ok":          res.Ok,
				"result_hash": res.ResultHash,
				"message":     res.Message,
			})
			return
		case <-deadlineCtx.Done():
			c.JSON(http.StatusAccepted, gin.H{
				"task_id": taskID,
				"warning": "dispatched; no result within 10s (still in progress)",
			})
			return
		}
	}
}

// compileWireRule converts the free-text REST fields to a CompiledRule proto.
func compileWireRule(id, dir, src, dst, proto, port, action string, mark uint32, natTo string, prio int32) (*myfwv1.CompiledRule, error) {
	directionMap := map[string]myfwv1.Direction{
		"":         myfwv1.Direction_DIRECTION_UNSPECIFIED,
		"INBOUND":  myfwv1.Direction_DIRECTION_INBOUND,
		"OUTBOUND": myfwv1.Direction_DIRECTION_OUTBOUND,
		"FORWARD":  myfwv1.Direction_DIRECTION_FORWARD,
	}
	protocolMap := map[string]myfwv1.Protocol{
		"":     myfwv1.Protocol_PROTOCOL_UNSPECIFIED,
		"ANY":  myfwv1.Protocol_PROTOCOL_ANY,
		"TCP":  myfwv1.Protocol_PROTOCOL_TCP,
		"UDP":  myfwv1.Protocol_PROTOCOL_UDP,
		"ICMP": myfwv1.Protocol_PROTOCOL_ICMP,
	}
	actionMap := map[string]myfwv1.Action{
		"":       myfwv1.Action_ACTION_UNSPECIFIED,
		"ACCEPT": myfwv1.Action_ACTION_ACCEPT,
		"DROP":   myfwv1.Action_ACTION_DROP,
		"REJECT": myfwv1.Action_ACTION_REJECT,
		"MARK":   myfwv1.Action_ACTION_MARK,
		"DNAT":   myfwv1.Action_ACTION_DNAT,
		"SNAT":   myfwv1.Action_ACTION_SNAT,
	}

	direction, ok := directionMap[dir]
	if !ok {
		return nil, jsonErr("bad direction: " + dir)
	}
	protocol, ok := protocolMap[proto]
	if !ok {
		return nil, jsonErr("bad protocol: " + proto)
	}
	act, ok := actionMap[action]
	if !ok {
		return nil, jsonErr("bad action: " + action)
	}

	return &myfwv1.CompiledRule{
		Id:          id,
		Direction:   direction,
		Source:      src,
		Destination: dst,
		Protocol:    protocol,
		PortRange:   port,
		Action:      act,
		Mark:        mark,
		NatTo:       natTo,
		Priority:    prio,
	}, nil
}

func defaultConfirmDeadline(seconds int64) time.Duration {
	if seconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(seconds) * time.Second
}

// jsonErr wraps a string as an error whose json.Marshal preserves it (helps
// when writing quick bad-request paths that would otherwise pull a helper).
func jsonErr(s string) error {
	return &jsonError{msg: s}
}

type jsonError struct{ msg string }

func (e *jsonError) Error() string                { return e.msg }
func (e *jsonError) MarshalJSON() ([]byte, error) { return json.Marshal(e.msg) }
