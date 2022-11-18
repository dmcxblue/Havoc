package agent

import (
	"Havoc/pkg/common"
	"Havoc/pkg/common/crypt"
	"Havoc/pkg/common/packer"
	"Havoc/pkg/common/parser"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/structs"
)

func BuildPayloadMessage(Jobs []Job, AesKey []byte, AesIv []byte) []byte {
	var (
		DataPayload        []byte
		PayloadPackage     []byte
		PayloadPackageSize = make([]byte, 4)
		DataCommandID      = make([]byte, 4)
	)

	for _, job := range Jobs {
		for i := range job.Data {
			switch job.Data[i].(type) {
			case int64:
				var xUint32 = make([]byte, 4)
				binary.LittleEndian.PutUint32(xUint32, uint32(job.Data[i].(int64)))
				DataPayload = append(DataPayload, xUint32...)
				break

			case int32:
				var integer32 = make([]byte, 4)
				binary.LittleEndian.PutUint32(integer32, uint32(job.Data[i].(int32)))
				DataPayload = append(DataPayload, integer32...)
				break

			case int:
				var integer32 = make([]byte, 4)
				binary.LittleEndian.PutUint32(integer32, uint32(job.Data[i].(int)))
				DataPayload = append(DataPayload, integer32...)
				break

			case uint32:
				var integer32 = make([]byte, 4)
				binary.LittleEndian.PutUint32(integer32, job.Data[i].(uint32))
				DataPayload = append(DataPayload, integer32...)
				break

			case string:
				var size = make([]byte, 4)
				binary.LittleEndian.PutUint32(size, uint32(len(job.Data[i].(string))))
				DataPayload = append(DataPayload, size...)
				DataPayload = append(DataPayload, []byte(job.Data[i].(string))...)
				break

			case []byte:
				var size = make([]byte, 4)
				binary.LittleEndian.PutUint32(size, uint32(len(job.Data[i].([]byte))))
				DataPayload = append(DataPayload, size...)
				DataPayload = append(DataPayload, job.Data[i].([]byte)...)
				break
			}
		}

		binary.LittleEndian.PutUint32(DataCommandID, job.Command)
		PayloadPackage = append(PayloadPackage, DataCommandID...)

		binary.LittleEndian.PutUint32(PayloadPackageSize, uint32(len(DataPayload)))
		PayloadPackage = append(PayloadPackage, PayloadPackageSize...)

		if len(DataPayload) > 0 {
			logger.Debug("DataPayload: \n", hex.Dump(DataPayload))
			DataPayload = crypt.XCryptBytesAES256(DataPayload, AesKey, AesIv)
			PayloadPackage = append(PayloadPackage, DataPayload...)
			DataPayload = nil
		}
	}

	logger.Debug("PayloadPackage:\n", hex.Dump(PayloadPackage))

	return PayloadPackage
}

func AgentParseHeader(data []byte) (AgentHeader, error) {
	var Header = AgentHeader{}
	var Parser = parser.NewParser(data)

	if Parser.Length() > 4 {
		Header.Size = Parser.ParseInt32()
	} else {
		return Header, errors.New("failed to parse package size")
	}

	if Parser.Length() > 4 {
		Header.MagicValue = Parser.ParseInt32()
	} else {
		return Header, errors.New("failed to parse magic value")
	}

	if Parser.Length() > 4 {
		Header.AgentID = Parser.ParseInt32()
	} else {
		return Header, errors.New("failed to parse agent id")
	}

	Header.Data = Parser

	logger.Debug(fmt.Sprintf("Header Size       : %d", Header.Size))
	logger.Debug(fmt.Sprintf("Header MagicValue : %x", Header.MagicValue))
	logger.Debug(fmt.Sprintf("Header AgentID    : %x", Header.AgentID))
	logger.Debug(fmt.Sprintf("Header Data       : \n%v", hex.Dump(Header.Data.Buffer())))

	return Header, nil
}

func AgentRegisterInfoToInstance(Header AgentHeader, RegisterInfo map[string]any) *Agent {
	var agent = &Agent{
		Active:     false,
		SessionDir: "",

		Info: new(AgentInfo),
	}
	var err error

	agent.NameID = fmt.Sprintf("%x", Header.AgentID)
	agent.Info.MagicValue = Header.MagicValue

	if val, ok := RegisterInfo["Hostname"]; ok {
		agent.Info.Hostname = val.(string)
	}

	if val, ok := RegisterInfo["Username"]; ok {
		agent.Info.Username = val.(string)
	}

	if val, ok := RegisterInfo["Domain"]; ok {
		agent.Info.DomainName = val.(string)
	}

	if val, ok := RegisterInfo["InternalIP"]; ok {
		agent.Info.InternalIP = val.(string)
	}

	if val, ok := RegisterInfo["Process Path"]; ok {
		agent.Info.ProcessPath = val.(string)
	}

	if val, ok := RegisterInfo["Process Name"]; ok {
		agent.Info.ProcessName = val.(string)
	}

	if val, ok := RegisterInfo["Process Arch"]; ok {
		agent.Info.ProcessArch = val.(string)
	}

	if val, ok := RegisterInfo["Process ID"]; ok {
		agent.Info.ProcessPID, err = strconv.Atoi(val.(string))
		if err != nil {
			logger.Debug("Couldn't parse ProcessID integer from string: " + err.Error())
			agent.Info.ProcessPID = 0
		}
	}

	if val, ok := RegisterInfo["Process Parent ID"]; ok {
		agent.Info.ProcessPPID, err = strconv.Atoi(val.(string))
		if err != nil {
			logger.Debug("Couldn't parse ProcessPPID integer from string: " + err.Error())
			agent.Info.ProcessPPID = 0
		}
	}

	if val, ok := RegisterInfo["Process Elevated"]; ok {
		agent.Info.Elevated = "false"
		if val == "1" {
			agent.Info.Elevated = "true"
		}
	}

	if val, ok := RegisterInfo["OS Version"]; ok {
		agent.Info.OSVersion = val.(string)
	}

	if val, ok := RegisterInfo["OS Build"]; ok {
		agent.Info.OSBuild = val.(string)
	}

	if val, ok := RegisterInfo["OS Arch"]; ok {
		agent.Info.OSArch = val.(string)
	}

	agent.Info.FirstCallIn = time.Now().Format("02/01/2006 15:04:05")
	agent.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05.999")
	agent.BackgroundCheck = false
	agent.Active = true

	return agent
}

func ParseResponse(AgentID int, Parser *parser.Parser) *Agent {
	logger.Debug("Response:\n" + hex.Dump(Parser.Buffer()))

	var (
		MagicValue  int
		DemonID     int
		Hostname    string
		DomainName  string
		Username    string
		InternalIP  string
		ProcessName string
		ProcessPID  int
		OsVersion   []int
		OsArch      int
		Elevated    int
		ProcessArch int
		ProcessPPID int
		SleepDelay  int
		AesKeyEmpty = make([]byte, 32)
	)

	/*
		[ SIZE         ] 4 bytes
		[ Magic Value  ] 4 bytes
		[ Agent ID     ] 4 bytes
		[ COMMAND ID   ] 4 bytes
		[ AES KEY      ] 32 bytes
		[ AES IV       ] 16 bytes
		AES Encrypted {
			[ Agent ID     ] 4 bytes // <-- this is needed to check if we successfully decrypted the data
			[ User Name    ] size + bytes
			[ Host Name    ] size + bytes
			[ Domain       ] size + bytes
			[ IP Address   ] 16 bytes?
			[ Process Name ] size + bytes
			[ Process ID   ] 4 bytes
			[ Parent  PID  ] 4 bytes
			[ Process Arch ] 4 bytes
			[ Elevated     ] 4 bytes
			[ OS Info      ] ( 5 * 4 ) bytes
			[ OS Arch      ] 4 bytes
			..... more
		}
	*/

	var Session = &Agent{
		Encryption: struct {
			AESKey []byte
			AESIv  []byte
		}{
			AESKey: Parser.ParseAtLeastBytes(32),
			AESIv:  Parser.ParseAtLeastBytes(16),
		},

		Active:     false,
		SessionDir: "",

		Info: new(AgentInfo),
	}

	logger.Debug("AES KEY\n" + hex.Dump(Session.Encryption.AESKey))
	logger.Debug("AES IV :\n" + hex.Dump(Session.Encryption.AESIv))

	logger.Debug("Buffer:\n" + hex.Dump(Parser.Buffer()))
	if bytes.Compare(Session.Encryption.AESKey, AesKeyEmpty) != 0 {
		Parser.DecryptBuffer(Session.Encryption.AESKey, Session.Encryption.AESIv)
	}
	logger.Debug("After Dec:\n" + hex.Dump(Parser.Buffer()))

	DemonID = Parser.ParseInt32()
	logger.Debug(fmt.Sprintf("Parsed DemonID: %x", DemonID))

	if AgentID != DemonID {
		if AgentID != 0 {
			logger.Debug("Failed to decrypt agent init request")
			return nil
		}
	} else {
		logger.Debug(fmt.Sprintf("AgentID (%x) == DemonID (%x)\n", AgentID, DemonID))
	}

	if Parser.Length() >= 4 {
		Hostname = string(Parser.ParseBytes())
	} else {
		logger.Debug("Failed to parse agent request")
		return nil
	}

	if Parser.Length() >= 4 {
		Username = string(Parser.ParseBytes())
	} else {
		logger.Debug("Failed to parse agent request")
		return nil
	}

	if Parser.Length() >= 4 {
		DomainName = string(Parser.ParseBytes())
	} else {
		logger.Debug("Failed to parse agent request")
		return nil
	}

	if Parser.Length() >= 4 {
		InternalIP = string(Parser.ParseBytes())
	} else {
		logger.Debug("Failed to parse agent request")
		return nil
	}

	logger.Debug(fmt.Sprintf(
		"\n"+
			"Hostname: %v\n"+
			"Username: %v\n"+
			"Domain  : %v\n"+
			"InternIP: %v\n",
		Hostname, Username, DomainName, InternalIP))

	ProcessName = string(Parser.ParseBytes())
	ProcessPID = Parser.ParseInt32()
	ProcessPPID = Parser.ParseInt32()
	ProcessArch = Parser.ParseInt32()
	Elevated = Parser.ParseInt32()

	logger.Debug(fmt.Sprintf(
		"\n"+
			"ProcessName: %v\n"+
			"ProcessPID : %v\n"+
			"ProcessPPID: %v\n"+
			"ProcessArch: %v\n"+
			"Elevated   : %v\n",
		ProcessName, ProcessPID, ProcessPPID, ProcessArch, Elevated))

	OsVersion = []int{Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32()}
	OsArch = Parser.ParseInt32()
	SleepDelay = Parser.ParseInt32()

	Session.Active = true

	Session.NameID = fmt.Sprintf("%x", DemonID)
	Session.Info.MagicValue = MagicValue
	Session.Info.FirstCallIn = time.Now().Format("02/01/2006 15:04:05")
	Session.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05.999")
	Session.Info.Hostname = Hostname
	Session.Info.DomainName = DomainName
	Session.Info.Username = Username
	Session.Info.InternalIP = InternalIP
	Session.Info.SleepDelay = SleepDelay

	// Session.Info.ExternalIP 	= strings.Split(connection.RemoteAddr().String(), ":")[0]
	// Session.Info.Listener 	= t.Name

	switch ProcessArch {

	case PROCESS_ARCH_UNKNOWN:
		Session.Info.ProcessArch = "Unknown"
		break

	case PROCESS_ARCH_X64:
		Session.Info.ProcessArch = "x64"
		break

	case PROCESS_ARCH_X86:
		Session.Info.ProcessArch = "x86"
		break

	case PROCESS_ARCH_IA64:
		Session.Info.ProcessArch = "IA64"
		break

	default:
		Session.Info.ProcessArch = "Unknown"
		break

	}

	Session.Info.OSVersion = getWindowsVersionString(OsVersion)

	switch OsArch {
	case 0:
		Session.Info.OSArch = "x86"
	case 9:
		Session.Info.OSArch = "x64/AMD64"
	case 5:
		Session.Info.OSArch = "ARM"
	case 12:
		Session.Info.OSArch = "ARM64"
	case 6:
		Session.Info.OSArch = "Itanium-based"
	default:
		Session.Info.OSArch = "Unknown (" + strconv.Itoa(OsArch) + ")"
	}

	Session.Info.Elevated = "false"
	if Elevated == 1 {
		Session.Info.Elevated = "true"
	}

	process := strings.Split(ProcessName, "\\")

	Session.Info.ProcessName = process[len(process)-1]
	Session.Info.ProcessPID = ProcessPID
	Session.Info.ProcessPPID = ProcessPPID
	Session.Info.ProcessPath = ProcessName
	Session.BackgroundCheck = false

	/*for {
	    if Parser.Length() >= 4 {
	        var Option = Parser.ParseInt32()

	        switch Option {
	        case DEMON_CHECKIN_OPTION_PIVOTS:
	            logger.Debug("DEMON_CHECKIN_OPTION_PIVOTS")
	              var PivotCount = Parser.ParseInt32()

	              logger.Debug("PivotCount: ", PivotCount)

	              for {
	                  if PivotCount == 0 {
	                      break
	                  }

	                  var (
	                      PivotAgentID = Parser.ParseInt32()
	                      PivotPackage = Parser.ParseBytes()
	                      PivotParser  = parser.NewParser(PivotPackage)
	                      PivotSession *Agent
	                  )

	                  var (
	                      _             = PivotParser.ParseInt32()
	                      HdrMagicValue = PivotParser.ParseInt32()
	                      _             = PivotParser.ParseInt32()
	                      _             = PivotParser.ParseInt32()
	                  )

	                  PivotSession = ParseResponse(PivotAgentID, PivotParser, RoutineFunc)
	                  if PivotSession != nil {
	                      PivotSession.Info.MagicValue = HdrMagicValue

	                      LogDemonCallback(PivotSession)
	                      RoutineFunc.AppendDemon(PivotSession)
	                      pk := RoutineFunc.EventNewDemon(PivotSession)
	                      RoutineFunc.EventAppend(pk)
	                      RoutineFunc.EventBroadcast("", pk)

	                      go PivotSession.BackgroundUpdateLastCallbackUI(RoutineFunc)

	                      Session.Pivots.Links = append(Session.Pivots.Links, PivotSession)

	                      PivotSession.Pivots.Parent = Session
	                  }

	                  PivotCount--
	              }

	            break
	        }

	    } else {
	        break
	    }
	}*/

	logger.Debug("Finished parsing demon")

	return Session
}

func (a *Agent) AddJobToQueue(job Job) []Job {
	a.JobQueue = append(a.JobQueue, job)
	return a.JobQueue
}

func (a *Agent) GetQueuedJobs() []Job {
	var Jobs = a.JobQueue

	a.JobQueue = nil

	return Jobs
}

func (a *Agent) UpdateLastCallback(routineFunc RoutineFunc) {
	var (
		OldLastCallIn, _ = time.Parse("02-01-2006 15:04:05", a.Info.LastCallIn)
		NewLastCallIn, _ = time.Parse("02-01-2006 15:04:05", time.Now().Format("02-01-2006 15:04:05"))
	)

	a.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05")

	diff := NewLastCallIn.Sub(OldLastCallIn)

	routineFunc.AgentCallback(a.NameID, diff.String())
}

func (a *Agent) BackgroundUpdateLastCallbackUI(routineFunc RoutineFunc) {
	if !a.BackgroundCheck {
		a.BackgroundCheck = true
	} else {
		return
	}

	for {
		if !a.Active {
			if len(a.Reason) == 0 {
				a.Reason = "Dead"
			}

			Callback := map[string]string{"Output": a.Reason}
			routineFunc.DemonOutput(a.NameID, COMMAND_NOJOB, Callback)
			return
		}

		var (
			OldLastCallIn, _ = time.Parse("02-01-2006 15:04:05", a.Info.LastCallIn)
			NewLastCallIn, _ = time.Parse("02-01-2006 15:04:05", time.Now().Format("02-01-2006 15:04:05"))
		)

		diff := NewLastCallIn.Sub(OldLastCallIn)

		routineFunc.AgentCallback(a.NameID, diff.String())

		time.Sleep(time.Second * 1)
	}
}

func (a *Agent) PivotAddJob(job Job) {
	var (
		Payload  = BuildPayloadMessage([]Job{job}, a.Encryption.AESKey, a.Encryption.AESIv)
		Packer   = packer.NewPacker(nil, nil)
		pivots   *Pivots
		PivotJob Job
		AgentID  int64
		err      error
	)

	// core package that the end pivot receive
	AgentID, err = strconv.ParseInt(a.NameID, 16, 32)
	if err != nil {
		logger.Debug("Failed to convert NameID string to AgentID: " + err.Error())
		return
	}

	Packer.AddInt32(int32(AgentID))
	Packer.AddBytes(Payload)

	PivotJob = Job{
		Command: COMMAND_PIVOT,
		Data: []interface{}{
			DEMON_PIVOT_SMB_COMMAND,
			AgentID,
			Packer.Buffer(),
		},
	}

	pivots = &a.Pivots

	// pack it up for all the parent pivots.
	for {
		if pivots.Parent.Pivots.Parent == nil {
			break
		}

		// create new layer package.
		Payload = BuildPayloadMessage([]Job{PivotJob}, pivots.Parent.Encryption.AESKey, pivots.Parent.Encryption.AESIv)
		Packer = packer.NewPacker(nil, nil)

		AgentID, err = strconv.ParseInt(pivots.Parent.NameID, 16, 32)
		if err != nil {
			logger.Debug("Failed to convert NameID string to AgentID: " + err.Error())
			return
		}

		Packer.AddInt32(int32(AgentID))
		Packer.AddBytes(Payload)

		PivotJob = Job{
			Command: COMMAND_PIVOT,
			Data: []interface{}{
				DEMON_PIVOT_SMB_COMMAND,
				AgentID,
				Packer.Buffer(),
			},
		}

		pivots = &pivots.Parent.Pivots
	}

	pivots.Parent.AddJobToQueue(PivotJob)
}

func (a *Agent) DownloadAdd(FileID int, FilePath string, FileSize int) error {
	var (
		err      error
		download = &Download{
			FileID:    FileID,
			FilePath:  FilePath,
			TotalSize: FileSize,
			Progress:  FileSize,
			State:     DOWNLOAD_STATE_RUNNING,
		}

		DemonPath        = logr.LogrInstance.AgentPath + "/" + a.NameID
		DemonDownloadDir = DemonPath + "/Download"
		DownloadFilePath = strings.Join(strings.Split(FilePath, "\\"), "/")
		FileSplit        = strings.Split(DownloadFilePath, "/")
		DownloadFile     = FileSplit[len(FileSplit)-1]
		DemonDownload    = DemonDownloadDir + "/" + strings.Join(FileSplit[:len(FileSplit)-1], "/")
	)

	/* check if we don't have a path traversal */
	path := filepath.Clean(DemonDownload)
	if !strings.HasPrefix(path, DemonDownloadDir) {
		logger.Error("File didn't started with agent download path. abort")
		return errors.New("File didn't started with agent download path. abort")
	}

	if _, err := os.Stat(DemonDownload); os.IsNotExist(err) {
		if err = os.MkdirAll(DemonDownload, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon download path" + a.NameID + ": " + err.Error())
			return errors.New("Failed to create Logr demon download path" + a.NameID + ": " + err.Error())
		}
	}

	/* remove null terminator. goland doesn't like it. */
	DownloadFile = common.StripNull(DownloadFile)

	download.File, err = os.Create(DemonDownload + "/" + DownloadFile)
	if err != nil {
		logger.Error("Failed to create file: " + err.Error())
		return errors.New("Failed to create file: " + err.Error())
	}

	download.LocalFile = DemonDownload + "/" + DownloadFile

	a.Downloads = append(a.Downloads, download)

	return nil
}

func (a *Agent) DownloadWrite(FileID int, data []byte) {
	for i := range a.Downloads {
		if a.Downloads[i].FileID == FileID {
			_, err := a.Downloads[i].File.Write(data)
			if err != nil {
				a.Downloads[i].File, err = os.Create(a.Downloads[i].LocalFile)
				if err != nil {
					logger.Error("Failed to create file: " + err.Error())
					return
				}

				_, err = a.Downloads[i].File.Write(data)
				if err != nil {
					logger.Error("Failed to write to file [" + a.Downloads[i].LocalFile + "]: " + err.Error())
				}

				a.Downloads[i].Progress += len(data)

				break
			}
			break
		}
	}
}

func (a *Agent) DownloadClose(FileID int) {
	for i := range a.Downloads {
		if a.Downloads[i].FileID == FileID {
			err := a.Downloads[i].File.Close()
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to close download (%x) file: %v", a.Downloads[i].FileID, err))
			}

			a.Downloads = append(a.Downloads[:i], a.Downloads[i+1:]...)
			break
		}
	}
}

func (a *Agent) DownloadGet(FileID int) *Download {
	for _, download := range a.Downloads {
		if download.FileID == FileID {
			return download
		}
	}
	return nil
}

func (a *Agent) PortFwdNew(SocketID, LclAddr, LclPort, FwdAddr, FwdPort int, Target string) {
	var portfwd = &PortFwd{
		Conn:    nil,
		SocktID: SocketID,
		LclAddr: LclAddr,
		LclPort: LclPort,
		FwdAddr: FwdAddr,
		FwdPort: FwdPort,
		Target:  Target,
	}

	a.PortFwds = append(a.PortFwds, portfwd)
}

func (a *Agent) PortFwdGet(SocketID int) *PortFwd {

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* return the found PortFwd object */
			return a.PortFwds[i]

		}

	}

	return nil
}

func (a *Agent) PortFwdOpen(SocketID int) error {
	var (
		err   error
		found bool
	)

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* alright we found our socket */
			found = true

			/* open the connection to the target */
			a.PortFwds[i].Conn, err = net.Dial("tcp", a.PortFwds[i].Target)
			if err != nil {
				return err
			}

		}

	}

	if !found {
		return fmt.Errorf("rportfwd socket id %x not found", SocketID)
	}

	return nil
}

func (a *Agent) PortFwdWrite(SocketID int, data []byte) error {
	var found bool

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* alright we found our socket */
			found = true

			if a.PortFwds[i].Conn != nil {

				/* write to the connection */
				_, err := a.PortFwds[i].Conn.Write(data)
				if err != nil {
					return err
				}

				break

			} else {
				return errors.New("portfwd connection is empty")
			}

		}

	}

	if !found {
		return fmt.Errorf("rportfwd socket id %x not found", SocketID)
	}

	return nil
}

func (a *Agent) PortFwdRead(SocketID int) ([]byte, error) {
	var (
		found = false
		data  = bytes.Buffer{}
	)

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* alright we found our socket */
			found = true

			if a.PortFwds[i].Conn != nil {

				/* read from our socket to the data buffer or return error */
				_, err := io.Copy(&data, a.PortFwds[i].Conn)
				if err != nil {
					return nil, err
				}

				break

			} else {
				return nil, errors.New("portfwd connection is empty")
			}

		}

	}

	if !found {
		return nil, fmt.Errorf("rportfwd socket id %x not found", SocketID)
	}

	/* return the read data */
	return data.Bytes(), nil
}

func (a *Agent) PortFwdClose(SocketID int) {

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* is there a socket? if not the not try anything or else we get an exception */
			if a.PortFwds[i].Conn != nil {

				/* close our connection */
				a.PortFwds[i].Conn.Close()

			}

			/* remove the socket from the array */
			a.PortFwds = append(a.PortFwds[:i], a.PortFwds[i+1:]...)

		}

	}

}

func (a *Agent) ToMap() map[string]interface{} {
	var TempParent = a.Pivots.Parent
	var InfoMap = structs.Map(a)

	a.Pivots.Parent = nil

	InfoMap["Info"].(map[string]interface{})["Listener"] = nil

	delete(InfoMap, "Connection")
	delete(InfoMap, "SessionDir")
	delete(InfoMap, "JobQueue")
	delete(InfoMap, "Parent")

	var TempMagic = fmt.Sprintf("%x", a.Info.MagicValue)

	if TempParent != nil {
		InfoMap["PivotParent"] = a.NameID
	}

	InfoMap["MagicValue"] = TempMagic

	return InfoMap
}

func (a *Agent) ToJson() string {
	// TODO: add Agents pivot links too

	jsonBytes, err := json.Marshal(a.ToMap())
	if err != nil {
		logger.Error("Failed to marshal object to json: " + err.Error())
		return ""
	}

	logger.Debug("jsonBytes =>", string(jsonBytes))

	return string(jsonBytes)
}

func (agents *Agents) AppendAgent(demon *Agent) []*Agent {
	agents.Agents = append(agents.Agents, demon)
	return agents.Agents
}

func getWindowsVersionString(OsVersion []int) string {
	var WinVersion = "Unknown"

	if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] != 0x0000001 && OsVersion[4] == 20348 {
		WinVersion = "Windows 2022 Server 22H2"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] != 0x0000001 && OsVersion[4] == 17763 {
		WinVersion = "Windows 2019 Server"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] == 0x0000001 && (OsVersion[4] >= 22000 && OsVersion[4] <= 22621) {
		WinVersion = "Windows 11"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows 2016 Server"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 10"
	} else if OsVersion[0] == 6 && OsVersion[1] == 3 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows Server 2012 R2"
	} else if OsVersion[0] == 6 && OsVersion[1] == 3 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 8.1"
	} else if OsVersion[0] == 6 && OsVersion[1] == 2 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows Server 2012"
	} else if OsVersion[0] == 6 && OsVersion[1] == 2 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 8"
	} else if OsVersion[0] == 6 && OsVersion[1] == 1 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows Server 2008 R2"
	} else if OsVersion[0] == 6 && OsVersion[1] == 1 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 7"
	}

	if OsVersion[3] != 0 {
		WinVersion += " Service Pack " + strconv.Itoa(OsVersion[3])
	}

	return WinVersion
}
