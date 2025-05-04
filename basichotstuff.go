package HotStuffDemo

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/niclabs/tcrsa"
	"github.com/theodocius271/HotStuffDemo/crypto"
	"google.golang.org/protobuf/proto"

	"github.com/theodocius271/HotStuffDemo/config"
	"github.com/theodocius271/HotStuffDemo/logging"
	pb "github.com/theodocius271/HotStuffDemo/proto"
)

var logger = logging.GetLogger()

func NewHotStuffImpl(id int, handleMethod func(string) string) *HotStuffImpl {
	msgEntrance := make(chan *pb.Msg)
	hsi := &HotStuffImpl{}
	hsi.MsgEntrance = msgEntrance
	hsi.ID = uint32(id)
	hsi.View = NewView(1, 1)
	logger.Debugf("[HOTSTUFF] Init block storage, replica id: %d", id)
	hsi.BlockStorage = NewBlockStorageImpl(strconv.Itoa(id))
	logger.Debugf("[HOTSTUFF] Generate genesis block")
	genesisBlock := GenerateGenesisBlock()
	err := hsi.BlockStorage.Put(genesisBlock)
	if err != nil {
		logger.Fatal("generate genesis block failed")
	}
	hsi.PrepareQC = &pb.QuorumCert{
		BlockHash: genesisBlock.Hash,
		Type:      pb.MsgType_PREPARE_VOTE,
		ViewNum:   0,
		Signature: nil,
	}
	hsi.PreCommitQC = &pb.QuorumCert{
		BlockHash: genesisBlock.Hash,
		Type:      pb.MsgType_PRECOMMIT_VOTE,
		ViewNum:   0,
		Signature: nil,
	}
	hsi.CommitQC = &pb.QuorumCert{
		BlockHash: genesisBlock.Hash,
		Type:      pb.MsgType_COMMIT_VOTE,
		ViewNum:   0,
		Signature: nil,
	}
	logger.Debugf("[HOTSTUFF] Init command set, replica id: %d", id)
	hsi.ReqSet = NewReqSet()

	// read config
	hsi.Config = config.HotStuffConfig{}
	hsi.Config.ReadConfig()

	// init timer and stop it
	hsi.TimeChan = NewTimer(hsi.Config.Timeout)
	hsi.TimeChan.Init()

	hsi.BatchTimeChan = NewTimer(hsi.Config.BatchTimeout)
	hsi.BatchTimeChan.Init()

	hsi.CurExec = &CurProp{
		Node:          nil,
		DocumentHash:  nil,
		PrepareVote:   make([]*tcrsa.SigShare, 0),
		PreCommitVote: make([]*tcrsa.SigShare, 0),
		CommitVote:    make([]*tcrsa.SigShare, 0),
		HighQC:        make([]*pb.QuorumCert, 0),
	}
	privateKey, err := crypto.ReadThresholdPrivateKeyFromFile(hsi.GetSelfInfo().PrivateKey)
	if err != nil {
		logger.Fatal(err)
	}
	hsi.Config.PrivateKey = privateKey
	hsi.ProcessMethod = handleMethod
	hsi.decided = false
	go hsi.receiveMsg()

	return hsi
}

func (hsi *HotStuffImpl) receiveMsg() {
	for {
		select {
		case msg, ok := <-hsi.MsgEntrance:
			if ok {
				go hsi.handleMsg(msg)
			}
		case <-hsi.TimeChan.Timeout():
			logger.Warn("Time out, goto new view")
			// set the duration of the timeout to 2 times
			hsi.TimeChan = NewTimer(hsi.Config.Timeout * 2)
			hsi.TimeChan.Init()
			hsi.ReqSet.UnMark(hsi.CurExec.Node.Commands...)
			hsi.BlockStorage.Put(hsi.CreateLeaf(hsi.CurExec.Node.ParentHash, nil))
			hsi.View.ViewNum++
			hsi.View.Primary = hsi.GetLeader()
			// check if self is the next leader
			if hsi.GetLeader() != hsi.ID {
				// if not, send next view mag to the next leader
				newViewMsg := hsi.Msg(pb.MsgType_NEWVIEW, nil, hsi.PrepareQC)
				hsi.Unicast(hsi.GetNetworkInfo()[hsi.GetLeader()], newViewMsg)
				// clear curExec
				hsi.CurExec = NewCurProposal()
			} else {
				hsi.decided = true
			}
		case <-hsi.BatchTimeChan.Timeout():
			hsi.BatchTimeChan.Init()
			hsi.batchEvent(hsi.ReqSet.GetFirst(int(hsi.Config.BatchSize)))
		}
	}
}

func (hsi *HotStuffImpl) processProposal() {
	// process proposal
	go hsi.ProcessProposal(hsi.CurExec.Node.Commands)
	// store block
	hsi.CurExec.Node.Committed = true
	go hsi.BlockStorage.Put(hsi.CurExec.Node)
	// add view number
	hsi.View.ViewNum++
	hsi.View.Primary = hsi.GetLeader()
	// check if self is the next leader
	if hsi.View.Primary != hsi.ID {
		// if not, send next view mag to the next leader
		newViewMsg := hsi.Msg(pb.MsgType_NEWVIEW, nil, hsi.PrepareQC)
		hsi.Unicast(hsi.GetNetworkInfo()[hsi.GetLeader()], newViewMsg)
		// clear curExec
		hsi.CurExec = NewCurProposal()
	} else {
		hsi.decided = true
	}
}

func (hsi *HotStuffImpl) batchEvent(cmds []string) {
	if len(cmds) == 0 {
		hsi.BatchTimeChan.SoftStartTimer()
		return
	}
	// create prepare msg
	node := hsi.CreateLeaf(hsi.BlockStorage.GetLastBlockHash(), cmds)
	hsi.CurExec.Node = node
	hsi.ReqSet.MarkProposed(cmds...)
	if hsi.HighQC == nil {
		hsi.HighQC = hsi.PrepareQC
	}
	prepareMsg := hsi.Msg(pb.MsgType_PREPARE, node, hsi.HighQC)
	// vote self
	marshal, _ := proto.Marshal(prepareMsg)
	hsi.CurExec.DocumentHash, _ = crypto.CreateDocumentHash(marshal, hsi.Config.PublicKey)
	partSig, _ := crypto.TSign(hsi.CurExec.DocumentHash, hsi.Config.PrivateKey, hsi.Config.PublicKey)
	hsi.CurExec.PrepareVote = append(hsi.CurExec.PrepareVote, partSig)
	// broadcast prepare msg
	hsi.Broadcast(prepareMsg)
	hsi.TimeChan.SoftStartTimer()
}

// handleMsg handle different msg with different way
func (hsi *HotStuffImpl) handleMsg(msg *pb.Msg) {
	switch msg.Payload.(type) {
	case *pb.Msg_NewView:
		logger.Debug("[HOTSTUFF NEWVIEW] Got new view msg")
		// process highqc and node
		hsi.CurExec.HighQC = append(hsi.CurExec.HighQC, msg.GetNewView().PrepareQC)
		if hsi.decided {
			if len(hsi.CurExec.HighQC) >= 2*hsi.Config.F {
				hsi.View.ViewChanging = true
				hsi.HighQC = hsi.PrepareQC
				for _, qc := range hsi.CurExec.HighQC {
					if qc.ViewNum > hsi.HighQC.ViewNum {
						hsi.HighQC = qc
					}
				}
				// TODO sync blocks if fall behind
				hsi.CurExec = NewCurProposal()
				hsi.View.ViewChanging = false
				hsi.BatchTimeChan.SoftStartTimer()
				hsi.decided = false
			}
		}
		//break
	case *pb.Msg_Prepare:
		logger.Debug("[HOTSTUFF PREPARE] Got prepare msg")
		if !hsi.MatchingMsg(msg, pb.MsgType_PREPARE) {
			logger.Warn("[HOTSTUFF PREPARE] msg does not match")
			return
		}
		prepare := msg.GetPrepare()
		if !bytes.Equal(prepare.CurProposal.ParentHash, prepare.HighQC.BlockHash) ||
			!hsi.SafeNode(prepare.CurProposal, prepare.HighQC) {
			logger.Warn("[HOTSTUFF PREPARE] node is not correct")
			return
		}
		// create prepare vote msg
		marshal, _ := proto.Marshal(msg)
		hsi.CurExec.DocumentHash, _ = crypto.CreateDocumentHash(marshal, hsi.Config.PublicKey)
		hsi.CurExec.Node = prepare.CurProposal
		partSig, _ := crypto.TSign(hsi.CurExec.DocumentHash, hsi.Config.PrivateKey, hsi.Config.PublicKey)
		partSigBytes, _ := json.Marshal(partSig)
		prepareVoteMsg := hsi.VoteMsg(pb.MsgType_PREPARE_VOTE, hsi.CurExec.Node, nil, partSigBytes)
		// send msg to leader
		hsi.Unicast(hsi.GetNetworkInfo()[hsi.GetLeader()], prepareVoteMsg)
		hsi.TimeChan.SoftStartTimer()
		//break
	case *pb.Msg_PrepareVote:
		logger.Debugf("[HOTSTUFF PREPARE-VOTE] Got prepare vote msg")
		if !hsi.MatchingMsg(msg, pb.MsgType_PREPARE_VOTE) {
			logger.Warn("[HOTSTUFF PREPARE-VOTE] Msg not match")
			return
		}
		// verify
		prepareVote := msg.GetPrepareVote()
		partSig := new(tcrsa.SigShare)
		_ = json.Unmarshal(prepareVote.PartialSig, partSig)
		if err := crypto.VerifyPartSig(partSig, hsi.CurExec.DocumentHash, hsi.Config.PublicKey); err != nil {
			logger.Warn("[HOTSTUFF PREPARE-VOTE] Partial signature is not correct")
			return
		}
		// put it into preparevote slice
		hsi.CurExec.PrepareVote = append(hsi.CurExec.PrepareVote, partSig)
		if len(hsi.CurExec.PrepareVote) == hsi.Config.F*2+1 {
			// create full signature
			signature, _ := crypto.CreateFullSignature(hsi.CurExec.DocumentHash, hsi.CurExec.PrepareVote, hsi.Config.PublicKey)
			qc := hsi.QC(pb.MsgType_PREPARE_VOTE, signature, prepareVote.BlockHash)
			hsi.PrepareQC = qc
			preCommitMsg := hsi.Msg(pb.MsgType_PRECOMMIT, hsi.CurExec.Node, qc)
			// broadcast msg
			hsi.Broadcast(preCommitMsg)
			hsi.TimeChan.SoftStartTimer()
		}
		//break
	case *pb.Msg_PreCommit:
		logger.Debug("[HOTSTUFF PRECOMMIT] Got precommit msg")
		if !hsi.MatchingQC(msg.GetPreCommit().PrepareQC, pb.MsgType_PREPARE_VOTE) {
			logger.Warn("[HOTSTUFF PRECOMMIT] QC not match")
			return
		}
		hsi.PrepareQC = msg.GetPreCommit().PrepareQC
		partSig, _ := crypto.TSign(hsi.CurExec.DocumentHash, hsi.Config.PrivateKey, hsi.Config.PublicKey)
		partSigBytes, _ := json.Marshal(partSig)
		preCommitVote := hsi.VoteMsg(pb.MsgType_PRECOMMIT_VOTE, hsi.CurExec.Node, nil, partSigBytes)
		hsi.Unicast(hsi.GetNetworkInfo()[hsi.GetLeader()], preCommitVote)
		hsi.TimeChan.SoftStartTimer()
		//break
	case *pb.Msg_PreCommitVote:
		logger.Debug("[HOTSTUFF PRECOMMIT-VOTE] Got precommit vote msg")
		if !hsi.MatchingMsg(msg, pb.MsgType_PRECOMMIT_VOTE) {
			logger.Warn("[HOTSTUFF PRECOMMIT-VOTE] Msg not match")
			return
		}
		// verify
		preCommitVote := msg.GetPreCommitVote()
		partSig := new(tcrsa.SigShare)
		_ = json.Unmarshal(preCommitVote.PartialSig, partSig)
		if err := crypto.VerifyPartSig(partSig, hsi.CurExec.DocumentHash, hsi.Config.PublicKey); err != nil {
			logger.Warn("[HOTSTUFF PRECOMMIT-VOTE] Partial signature is not correct")
			return
		}
		hsi.CurExec.PreCommitVote = append(hsi.CurExec.PreCommitVote, partSig)
		if len(hsi.CurExec.PreCommitVote) == 2*hsi.Config.F+1 {
			signature, _ := crypto.CreateFullSignature(hsi.CurExec.DocumentHash, hsi.CurExec.PreCommitVote, hsi.Config.PublicKey)
			preCommitQC := hsi.QC(pb.MsgType_PRECOMMIT_VOTE, signature, hsi.CurExec.Node.Hash)
			// vote self
			hsi.PreCommitQC = preCommitQC
			commitMsg := hsi.Msg(pb.MsgType_COMMIT, hsi.CurExec.Node, preCommitQC)
			hsi.Broadcast(commitMsg)
			hsi.TimeChan.SoftStartTimer()
		}
		//break
	case *pb.Msg_Commit:
		logger.Debug("[HOTSTUFF COMMIT] Got commit msg")
		commit := msg.GetCommit()
		if !hsi.MatchingQC(commit.PreCommitQC, pb.MsgType_PRECOMMIT_VOTE) {
			logger.Warn("[HOTSTUFF COMMIT] QC not match")
			return
		}
		hsi.PreCommitQC = commit.PreCommitQC
		partSig, _ := crypto.TSign(hsi.CurExec.DocumentHash, hsi.Config.PrivateKey, hsi.Config.PublicKey)
		partSigBytes, _ := json.Marshal(partSig)
		commitVoteMsg := hsi.VoteMsg(pb.MsgType_COMMIT_VOTE, hsi.CurExec.Node, nil, partSigBytes)
		hsi.Unicast(hsi.GetNetworkInfo()[hsi.GetLeader()], commitVoteMsg)
		hsi.TimeChan.SoftStartTimer()
		//break
	case *pb.Msg_CommitVote:
		logger.Debug("[HOTSTUFF COMMIT-VOTE] Got commit vote msg")
		if !hsi.MatchingMsg(msg, pb.MsgType_COMMIT_VOTE) {
			logger.Warn("[HOTSTUFF COMMIT-VOTE] Msg not match")
			return
		}
		commitVoteMsg := msg.GetCommitVote()
		partSig := new(tcrsa.SigShare)
		_ = json.Unmarshal(commitVoteMsg.PartialSig, partSig)
		if err := crypto.VerifyPartSig(partSig, hsi.CurExec.DocumentHash, hsi.Config.PublicKey); err != nil {
			logger.Warn("[HOTSTUFF COMMIT-VOTE] Partial signature is not correct")
			return
		}
		hsi.CurExec.CommitVote = append(hsi.CurExec.CommitVote, partSig)
		if len(hsi.CurExec.CommitVote) == 2*hsi.Config.F+1 {
			signature, _ := crypto.CreateFullSignature(hsi.CurExec.DocumentHash, hsi.CurExec.CommitVote, hsi.Config.PublicKey)
			commitQC := hsi.QC(pb.MsgType_COMMIT_VOTE, signature, hsi.CurExec.Node.Hash)
			// vote self
			hsi.CommitQC = commitQC
			decideMsg := hsi.Msg(pb.MsgType_DECIDE, hsi.CurExec.Node, commitQC)
			hsi.Broadcast(decideMsg)
			hsi.TimeChan.Stop()
			hsi.processProposal()
		}
		//break
	case *pb.Msg_Decide:
		logger.Debug("[HOTSTUFF DECIDE] Got decide msg")
		decideMsg := msg.GetDecide()
		if !hsi.MatchingQC(decideMsg.CommitQC, pb.MsgType_COMMIT_VOTE) {
			logger.Warn("[HOTSTUFF DECIDE] QC not match")
			return
		}
		hsi.CommitQC = decideMsg.CommitQC
		hsi.TimeChan.Stop()
		hsi.processProposal()
		//break
	case *pb.Msg_Request:
		request := msg.GetRequest()
		logger.Debugf("[HOTSTUFF] Got request msg, content:%s", request.String())
		// put the cmd into the cmdset
		hsi.ReqSet.Add(request.Cmd)
		// send request to the leader, if the replica is not the leader
		if hsi.ID != hsi.GetLeader() {
			hsi.Unicast(hsi.GetNetworkInfo()[hsi.GetLeader()], msg)
			return
		}
		if hsi.CurExec.Node != nil || hsi.View.ViewChanging {
			return
		}
		// start batch timer
		hsi.BatchTimeChan.SoftStartTimer()
		// if the length of unprocessed cmd equals to batch size, stop timer and call handleMsg to send prepare msg
		logger.Debugf("cmd set size: %d", len(hsi.ReqSet.GetFirst(int(hsi.Config.BatchSize))))
		cmds := hsi.ReqSet.GetFirst(int(hsi.Config.BatchSize))
		if len(cmds) == int(hsi.Config.BatchSize) {
			// stop timer
			hsi.BatchTimeChan.Stop()
			// create prepare msg
			hsi.batchEvent(cmds)
		}
		//break
	default:
		logger.Warn("Unsupported msg type, drop it.")
		//break
	}
}
