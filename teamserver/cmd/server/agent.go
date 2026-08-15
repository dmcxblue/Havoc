package server

import (
	"Havoc/pkg/logger"
	"encoding/json"
	"math/rand"
	"time"
	"fmt"
	"strconv"

	"Havoc/pkg/agent"
	"Havoc/pkg/events"
	"Havoc/pkg/packager"
)

func (t *Teamserver) AgentUpdate(agent *agent.Agent) {
	err := t.DB.AgentUpdate(agent)
	if err != nil {
		logger.Error("Could not update agent: " + err.Error())
	}
}

func (t *Teamserver) Died(Agent *agent.Agent) {
	Agent.Active = false
	t.UnlinkFromAll(Agent)
	t.EventAgentMark(Agent.NameID, "Dead")
	t.AgentUpdate(Agent)
}

func (t *Teamserver) UnlinkFromAll(Agent *agent.Agent) {
	// remove all links from agent using reverse iteration to avoid skipping elements
	for i := len(Agent.Pivots.Links) - 1; i >= 0; i-- {
		t.LinkRemove(Agent, Agent.Pivots.Links[i], false)
		Agent.Pivots.Links = append(Agent.Pivots.Links[:i], Agent.Pivots.Links[i+1:]...)
	}

	// remove agent from parent's link
	t.Agents.RLock()
	agents := t.Agents.Agents
	t.Agents.RUnlock()

	for _, ParentAgent := range agents {
		if ParentAgent.NameID == Agent.NameID {
			continue
		}

		for i := range ParentAgent.Pivots.Links {
			if ParentAgent.Pivots.Links[i].NameID == Agent.NameID {
				t.LinkRemove(ParentAgent, Agent, false)
				ParentAgent.Pivots.Links = append(ParentAgent.Pivots.Links[:i], ParentAgent.Pivots.Links[i+1:]...)
				break
			}
		}
	}
}

func (t *Teamserver) ParentOf(Agent *agent.Agent) (int, error) {
	AgentID, err := strconv.ParseInt(Agent.NameID, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse agent NameID: %w", err)
	}

	ID, err := t.DB.ParentOf(int(AgentID))
	return ID, err
}

func (t *Teamserver) LinksOf(Agent *agent.Agent) []int {
	AgentID, err := strconv.ParseInt(Agent.NameID, 16, 64)
	if err != nil {
		logger.Error("Failed to parse agent NameID in LinksOf: " + err.Error())
		return nil
	}

	return t.DB.LinksOf(int(AgentID))
}

func (t *Teamserver) LinkAdd(ParentAgent *agent.Agent, LinkAgent *agent.Agent) error {
	ParentAgentID, err := strconv.ParseInt(ParentAgent.NameID, 16, 64)
	if err != nil {
		return fmt.Errorf("failed to parse ParentAgent NameID: %w", err)
	}
	LinkAgentID, err := strconv.ParseInt(LinkAgent.NameID, 16, 64)
	if err != nil {
		return fmt.Errorf("failed to parse LinkAgent NameID: %w", err)
	}

	err = t.DB.LinkAdd(int(ParentAgentID), int(LinkAgentID))
	if err != nil {
		logger.Error("Could not add link to database: " + err.Error())
		return err
	}

	return nil
}

func (t *Teamserver) LinkRemove(ParentAgent *agent.Agent, LinkAgent *agent.Agent, UpdateLinks bool) {
	ParentAgentID, err := strconv.ParseInt(ParentAgent.NameID, 16, 64)
	if err != nil {
		logger.Error("Failed to parse ParentAgent NameID in LinkRemove: " + err.Error())
		return
	}
	LinkAgentID, err := strconv.ParseInt(LinkAgent.NameID, 16, 64)
	if err != nil {
		logger.Error("Failed to parse LinkAgent NameID in LinkRemove: " + err.Error())
		return
	}

	LinkAgent.Active = false
	LinkAgent.Reason = "Disconnected"

	if UpdateLinks {
		for i := range ParentAgent.Pivots.Links {
			if ParentAgent.Pivots.Links[i].NameID == LinkAgent.NameID {
				ParentAgent.Pivots.Links = append(ParentAgent.Pivots.Links[:i], ParentAgent.Pivots.Links[i+1:]...)
				break
			}
		}
	}

	err = t.DB.LinkRemove(int(ParentAgentID), int(LinkAgentID))
	if err != nil {
		logger.Error("Could not remove link to database: " + err.Error())
	}

	t.AgentUpdate(LinkAgent)
}

func (t *Teamserver) AgentHasDied(Agent *agent.Agent) bool {
	var AgentID, _ = strconv.ParseInt(Agent.NameID, 16, 64)

	return t.DB.AgentHasDied(int(AgentID))
}

func (t *Teamserver) AgentAdd(Agent *agent.Agent) []*agent.Agent {
	if Agent != nil {
		if t.WebHooks != nil {
			t.WebHooks.NewAgent(Agent.ToMap())
		}
	}

	err := t.DB.AgentAdd(Agent)
	if err != nil {
		logger.Error("Could not add agent to database: " + err.Error())
	}

	return t.Agents.AgentsAppend(Agent)
}

func (t *Teamserver) AgentRemove(AgentID string) {
	var AgentIDInt, err = strconv.ParseInt(AgentID, 16, 64)
	if err != nil {
		logger.Error("Failed to parse AgentID: " + err.Error())
		return
	}

	// Remove from database
	err = t.DB.AgentRemove(int(AgentIDInt))
	if err != nil {
		logger.Error("Could not remove agent from database: " + err.Error())
	}

	// Remove from in-memory slice
	t.Agents.AgentsRemove(AgentID)

	// Broadcast removal to all clients
	var pk = events.Demons.DemonRemove(AgentID)
	t.EventAppend(pk)
	t.EventBroadcast("", pk)

	logger.Info("Agent " + AgentID + " removed")
}

func (t *Teamserver) AgentSendNotify(Agent *agent.Agent) {

	var pk packager.Package

	/* create a new agent package */
	pk = t.EventNewDemon(Agent)

	/* append the new agent event */
	t.EventAppend(pk)

	/* send it to every connected client */
	t.EventBroadcast("", pk)

}

func (t *Teamserver) AgentCallbackSize(DemonInstance *agent.Agent, i int) {
	var (
		Message = make(map[string]string)
		pk      packager.Package
	)

	Message["Type"] = "Good"
	Message["Message"] = fmt.Sprintf("Send Task to Agent [%v bytes]", i)

	OutputJson, _ := json.Marshal(Message)

	pk = events.Demons.DemonOutput(DemonInstance.NameID, agent.HAVOC_CONSOLE_MESSAGE, string(OutputJson))

	t.EventAppend(pk)
	t.EventBroadcast("", pk)
}

func (t *Teamserver) AgentInstance(AgentID int) *agent.Agent {
	t.Agents.RLock()
	defer t.Agents.RUnlock()

	for _, demon := range t.Agents.Agents {
		var NameID, _ = strconv.ParseInt(demon.NameID, 16, 64)

		if AgentID == int(NameID) {
			return demon
		}
	}
	return nil
}

func (t *Teamserver) AgentLastTimeCalled(AgentID string, LastCallback string, Sleep int, Jitter int, KillDate int64, WorkingHours int32) {
	var (
		Output = map[string]string{
			"Last": LastCallback,
			"Sleep": fmt.Sprintf("%d", Sleep),
			"Jitter": fmt.Sprintf("%d", Jitter),
			"KillDate": fmt.Sprintf("%d", KillDate),
			"WorkingHours": fmt.Sprintf("%d", WorkingHours),
		}

		out, _ = json.Marshal(Output)
		pk     = events.Demons.DemonOutput(AgentID, agent.COMMAND_NOJOB, string(out))
	)

	t.EventBroadcast("", pk)
}

func (t *Teamserver) AgentExist(AgentID int) bool {
	t.Agents.RLock()
	defer t.Agents.RUnlock()

	for _, demon := range t.Agents.Agents {
		var NameID, err = strconv.ParseInt(demon.NameID, 16, 64)
		if err != nil {
			logger.Debug("Failed to convert demon.NameID to int: " + err.Error())
			return false
		}

		if AgentID == int(NameID) {
			return true
		}
	}
	return false
}

func (t *Teamserver) AgentByNameID(nameID string) *agent.Agent {
	t.Agents.RLock()
	defer t.Agents.RUnlock()

	for _, demon := range t.Agents.Agents {
		if demon.NameID == nameID {
			return demon
		}
	}
	return nil
}

func (t *Teamserver) AgentConsole(AgentID string, CommandID int, Output map[string]string) {
	var (
		out, _ = json.Marshal(Output)
		pk     = events.Demons.DemonOutput(AgentID, CommandID, string(out))
	)

	t.EventAppend(pk)
	t.EventBroadcast("", pk)
}

func (t *Teamserver) PythonModuleCallback(ClientID string, AgentID string, CommandID int, Output map[string]string) {
	var (
		out, _ = json.Marshal(Output)
		pk     = events.Demons.DemonOutput(AgentID, CommandID, string(out))
	)

	err := t.SendEvent(ClientID, pk)
	if err != nil {
		logger.Error("SendEvent error: ", err)
	}
}

func (t *Teamserver) AgentCallback(DemonID string, Time string) {
	var (
		Output = map[string]string{
			"Output": Time,
		}

		out, _ = json.Marshal(Output)
		pk     = events.Demons.DemonOutput(DemonID, agent.COMMAND_NOJOB, string(out))
	)

	t.EventBroadcast("", pk)
}

func (t *Teamserver) SendLogs() bool {
	return t.Flags.Server.SendLogs
}

func (t *Teamserver) GetDotNetPipeTemplate() string {
	PipeTemplate := t.Profile.Config.Demon.DotNetNamePipe

	// https://gist.github.com/realoriginal/d9178c9b071707fec2d6de89a63e4709

	PipeTemplates := []string{
		"Winsock2\\\\CatalogChangeListener-$#-0",
		"mojo.{pid}.{tid}.####################",
		"crashpad_{pid}_@@@@@@@@@@@@@@@@",
		"chrome.sync.{pid}.{tid}.########",
	}

	if PipeTemplate == "" {
		rand.Seed(time.Now().UnixNano())
		index := rand.Intn(len(PipeTemplates))
		PipeTemplate = PipeTemplates[index]
	}

	return PipeTemplate
}
