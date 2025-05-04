package config

import (
	"time"

	"github.com/niclabs/tcrsa"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/theodocius271/HotStuffDemo/crypto"
	"github.com/theodocius271/HotStuffDemo/logging"
)

var logger = logging.GetLogger()

type HotStuffConfig struct {
	NetworkType    string `mapstructure:"type"`
	BatchSize      uint64 `mapstructure:"batch-size"`
	LeaderSchedule []int  `mapstructure:"leader-schedule"`
	BatchTimeout   time.Duration
	Timeout        time.Duration
	PublicKey      *tcrsa.KeyMeta
	PrivateKey     *tcrsa.KeyShare
	Cluster        []*ReplicaInfo
	N              int
	F              int
}

func NewHotStuffConfig() *HotStuffConfig {
	config := &HotStuffConfig{}
	config.ReadConfig()
	return config
}

type ReplicaInfo struct {
	ID         uint32
	Address    string `mapstructure:"listen-address"`
	PrivateKey string `mapstructure:"privatekeypath"`
}

// ReadConfig reads hotstuff config from yaml file
func (hsc *HotStuffConfig) ReadConfig() {
	logger.Debug("[HOTSTUFF] Read config")
	viper.AddConfigPath("/opt/hotstuff/config/")
	viper.AddConfigPath("../config")
	viper.AddConfigPath("../../config")
	viper.AddConfigPath("./config")
	viper.SetConfigName("hotstuff")
	err := viper.ReadInConfig()
	if err != nil {
		logger.Fatal(err)
	}
	networkType := viper.GetString("hotstuff.type")
	hsc.NetworkType = networkType
	batchTimeout := viper.GetDuration("hotstuff.batchtimeout")
	logger.Debugf("batchtimeout = %v", batchTimeout)
	hsc.BatchTimeout = batchTimeout
	timeout := viper.GetDuration("hotstuff.timeout")
	logger.Debugf("timeout = %v", timeout)
	hsc.Timeout = timeout
	batchSize := viper.GetUint64("hotstuff.batch-size")
	logrus.Debugf("batch size = %d", batchSize)
	hsc.BatchSize = batchSize
	leaderSchedule := viper.GetIntSlice("hotstuff.leader-schedule")
	logrus.Debugf("leader schedule = %v", leaderSchedule)
	hsc.LeaderSchedule = leaderSchedule
	publicKeyPath := viper.GetString("crypto.pubkeypath")
	publicKey, err := crypto.ReadThresholdPublicKeyFromFile(publicKeyPath)
	if err != nil {
		logger.Fatal(err)
	}
	hsc.PublicKey = publicKey
	err = viper.UnmarshalKey("hotstuff.cluster", &hsc.Cluster)
	if err != nil {
		logger.Fatal(err)
	}
	hsc.N = viper.GetInt("hotstuff.N")
	hsc.F = viper.GetInt("hotstuff.f")
}
