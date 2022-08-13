package qy_weixin

import (
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"os"
	"sync"
	"time"
)

const (
	TOKEN_URL    = "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%v&corpsecret=%v"
	SEND_MSG_URL = "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=%v"
)

const (
	CORP_ID     = "CORP_ID"
	CORP_SECRET = "CORP_SECRET"
)

type AccessToken struct {
	Token      string
	ExpireTime time.Time
}

type BaseResult struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

type TokenResult struct {
	*BaseResult
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type qyWeixinService struct{}

var QyWeixinService = new(qyWeixinService)

var lck sync.Mutex

var accessToken *AccessToken

var client = resty.New()

func (q *qyWeixinService) getConfFromEnv(key string, defaultVal string) (string, error) {
	val := os.Getenv(key)
	if len(val) == 0 && len(defaultVal) == 0 {
		return "", errors.New(fmt.Sprintf("[%v]获取不到配置", key))
	} else if len(val) == 0 {
		return defaultVal, nil
	} else {
		return val, nil
	}
}

func (q *qyWeixinService) GetAccessToken(forceFresh bool) (string, error) {
	if !forceFresh {
		if accessToken != nil && time.Now().Before(accessToken.ExpireTime) {
			return accessToken.Token, nil
		}
	}

	lck.Lock()
	defer lck.Unlock()

	corpId, err := q.getConfFromEnv(CORP_ID, "")
	if err != nil {
		return "", err
	}
	corpSecret, err := q.getConfFromEnv(CORP_SECRET, "")
	if err != nil {
		return "", err
	}
	result := &TokenResult{}
	_, err = client.R().SetResult(result).Get(fmt.Sprintf(TOKEN_URL, corpId, corpSecret))

	if err != nil {
		return "", nil
	}

	if result.ErrCode != 0 {
		return "", errors.New(result.ErrMsg)
	}

	accessToken = &AccessToken{
		Token:      result.AccessToken,
		ExpireTime: time.Now().Add(time.Second * time.Duration(result.ExpiresIn)),
	}
	return accessToken.Token, nil
}

func (s *qyWeixinService) SendMsg(body string) (bool, error) {

	token, err := s.GetAccessToken(false)
	if err != nil {
		return false, err
	}

	result := &BaseResult{}

	_, err = client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(body).
		SetResult(&result).
		Post(fmt.Sprintf(SEND_MSG_URL, token))
	if err != nil {
		return false, err
	}
	if result.ErrCode == 0 {
		return true, nil
	}
	return false, errors.New(result.ErrMsg)
}
