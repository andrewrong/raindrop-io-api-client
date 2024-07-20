// Package raindrop implements Raindrop.io API client.
//
// API Reference: https://developer.raindrop.io/
package raindrop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

const (
	apiHost  = "https://api.raindrop.io"
	authHost = "https://raindrop.io"

	endpointAuthorize   = "/oauth/authorize"
	authorizeUri        = endpointAuthorize + "?client_id=%s&redirect_uri=%s"
	endpointAccessToken = "/oauth/access_token"

	// 获得root下面所有的集合(文件夹)
	endpointGetRootCollections = "/rest/v1/collections"
	// 获得某一个collection下面的所有的集合
	endpointGetChildCollections = "/rest/v1/collections/childrens"
	// 获得集合信息
	endpointGetCollection = "/rest/v1/collection/"
	// 创建一个集合
	endpointCreateCollection = "/rest/v1/collection"

	// 获得单条item的具体信息
	endpointRaindrop = "/rest/v1/raindrop"
	// 多条item的信息更新和创建
	endpointRaindrops = "/rest/v1/raindrops/"
	// tag
	endpointTags = "/rest/v1/tags"

	defaultTimeout = 5 * time.Second
)

// Client is a raindrop client
type Client struct {
	apiURL       *url.URL
	authURL      *url.URL
	httpClient   *http.Client
	clientId     string
	clientSecret string
	redirectUri  string
	ClientCode   string
}

// AccessTokenResponse represents the token exchange api response item
type AccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Expires      int    `json:"expires,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Error        string `json:"error,omitempty"`
}

// accessTokenRequest represents the token exchange api request item
type accessTokenRequest struct {
	Code         string `json:"code"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectUri  string `json:"redirect_uri"`
	GrantType    string `json:"grant_type"`
}

// refreshTokenRequest represents the token refresh api request item
type refreshTokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
}

// createCollectionRequest represents create collection api request item
type createCollectionRequest struct {
	View     string   `json:"view,omitempty"`       // collection的展示样式
	Title    string   `json:"title,omitempty"`      // name
	Sort     int      `json:"sort,omitempty"`       // 排序的方式
	Public   bool     `json:"public,omitempty"`     // 公开
	ParentId uint32   `json:"parent.$id,omitempty"` // 对应的父类的id，没有就是root目录
	Cover    []string `json:"cover,omitempty"`      // 收藏的封面网址
}

// CreateCollectionResponse represents create collection api response item
type CreateCollectionResponse struct {
	Result       bool                    `json:"result"`
	Item         createCollectionRequest `json:"item,omitempty"`
	Error        string                  `json:"error,omitempty"`
	ErrorMessage string                  `json:"errorMessage,omitempty"`
}

// access represents collections access level and drag possibility from collection
// to another one
type access struct {
	Level     int  `json:"level"`
	Draggable bool `json:"draggable"`
}

// UserRef represents collection's owner
type UserRef struct {
	Id  int    `json:"$id"`
	Ref string `json:"$ref"`
}

// media represents cover link
type media struct {
	Link string `json:"link"`
	Type string `json:"type"`
}

type pleaseParse struct{}

// Collection represents Raindrop.io collection type
type Collection struct {
	ID         uint32   `json:"_id"`
	Access     access   `json:"access"`
	Color      string   `json:"color"`
	Count      uint32   `json:"count"`
	Cover      []string `json:"cover"`
	Created    string   `json:"created"`
	LastUpdate string   `json:"lastUpdate"`
	ParentId   int      `json:"parent_id,omitempty"`
	Expanded   bool     `json:"expanded"`
	Public     bool     `json:"public"`
	Title      string   `json:"title"`
	User       UserRef  `json:"user"`
	View       string   `json:"view"`
}

type CollectionRef struct {
	Ref             string `json:"$ref"`
	CollectionId    uint32 `json:"$id"`
	OldCollectionId uint32 `json:"oid"`
}

// GetCollectionsResponse represents get root and child collections api response
type GetCollectionsResponse struct {
	Result bool         `json:"result"`
	Items  []Collection `json:"items"`
}

// GetCollectionResponse represents get collection by id api response
type GetCollectionResponse struct {
	Result bool       `json:"result"`
	Item   Collection `json:"item"`
}

type RaindropUserInfo struct {
	ID         uint32   `json:"_id"` // id
	Created    string   `json:"created,omitempty"`
	LastUpdate string   `json:"lastUpdate,omitempty"`
	Sort       int      `json:"sort,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Media      []media  `json:"media,omitempty"`
	Cover      string   `json:"cover,omitempty"`
	Type       string   `json:"type,omitempty"`
	HTML       string   `json:"html,omitempty"`
	Excerpt    string   `json:"excerpt,omitempty"`
	Title      string   `json:"title,omitempty"`
	Link       string   `json:"link"`
	Domain     string   `json:"domain"`
	Note       string   `json:"note,omitempty"` // note limit 0 - 10000
	User       UserRef  `json:"user"`
	Removed    bool     `json:"removed"`

	Collection   CollectionRef  `json:"collection,omitempty"` // 貌似无效的字段;
	CollectionId uint32         `json:"collectionId"`         // 和collection类似,估计是新老字段吧;
	FileInfo     AttachFileInfo `json:"file,omitempty"`
	Important    bool           `json:"important"` //表示是否重要，红心
	Highlights   []Highlight    `json:"highlights,omitempty"`
	Reminder     Reminder       `json:"reminder,omitempty"`
}

// Raindrop represents get raindrops api response item
type Raindrop struct {
	RaindropUserInfo
	RaindropAttach
}

type RaindropAttach struct {
	Broken bool          `json:"broken"`
	Cache  RaindropCache `json:"cache"`
	CRef   CreatorRef    `json:"creatorRef,omitempty"`
}

type Highlight struct {
	Id      string `json:"_id"`
	Text    string `json:"text"`
	Color   string `json:"color"`
	Note    string `json:"note"`
	Created string `json:"created"`
}

type CreatorRef struct {
	Id     uint32 `json:"_id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Avatar string `json:"avatar"`
}

type AttachFileInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size uint32 `json:"size"`
}

type CacheStatus string

const (
	READY        CacheStatus = "ready"
	RETRY        CacheStatus = "retry"
	FAILED       CacheStatus = "failed"
	INVALID_O    CacheStatus = "invalid-origin"
	INVALID_TO   CacheStatus = "invalid-timeout"
	INVALID_SIZE CacheStatus = "invalid-size"
)

type RaindropCache struct {
	Status  CacheStatus `json:"status"`
	Size    uint32      `json:"size"`
	Created string      `json:"created"`
}

type Reminder struct {
	Date string `json:"date"`
}

// SingleRaindropResponse represent single raindrop api response
type SingleRaindropResponse struct {
	Result bool     `json:"result"`
	Items  Raindrop `json:"item"`
}

// MultiRaindropsResponse represents get multiple raindrops api response
type MultiRaindropsResponse struct {
	Result bool       `json:"result"`
	Items  []Raindrop `json:"items"`
}

// Tag represents get tags api response item
type Tag struct {
	ID    string `json:"_id"`
	Count int    `json:"count"`
}

// Tags represents get tags api response
type Tags struct {
	Result bool  `json:"result"`
	Items  []Tag `json:"items"`
}

// NewClient creates Raindrop.io client
func NewClient(clientId string, clientSecret string, redirectUri string) (*Client, error) {
	auth, err := url.Parse(authHost)
	if err != nil {
		return nil, err
	}
	api, err := url.Parse(apiHost)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}
	client := Client{
		apiURL:  api,
		authURL: auth,
		httpClient: &http.Client{
			Timeout:   defaultTimeout,
			Transport: tr,
		},
		clientId:     clientId,
		clientSecret: clientSecret,
		redirectUri:  redirectUri,
	}

	return &client, nil
}

// GetRootCollections call Get root collections API.
// Reference: https://developer.raindrop.io/v1/collections/methods#get-root-collections
func (c *Client) GetRootCollections(accessToken string, ctx context.Context) (*GetCollectionsResponse, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointGetRootCollections)

	req, err := c.newRequest(accessToken, http.MethodGet, u, nil, ctx)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	r := new(GetCollectionsResponse)
	if err := parseResponse(response, 200, &r); err != nil {
		return nil, err
	}

	return r, nil
}

// GetChildCollections call Get child collections API.
// Reference: https://developer.raindrop.io/v1/collections/methods#get-child-collections
func (c *Client) GetChildCollections(accessToken string, ctx context.Context) (*GetCollectionsResponse, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointGetChildCollections)

	req, err := c.newRequest(accessToken, http.MethodGet, u, nil, ctx)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	result := new(GetCollectionsResponse)
	if err = parseResponse(resp, 200, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCollection call Get collection API.
// Reference: https://developer.raindrop.io/v1/collections/methods#get-collection
func (c Client) GetCollection(accessToken string, id uint32, ctx context.Context) (*GetCollectionResponse, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointGetCollection+strconv.Itoa(int(id)))

	req, err := c.newRequest(accessToken, http.MethodGet, u, nil, ctx)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	result := new(GetCollectionResponse)
	if err = parseResponse(resp, 200, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateCollection creates new Collection
// Reference: https://developer.raindrop.io/v1/collections/methods#create-collection
func (c *Client) CreateCollection(accessToken string, isRoot bool, view string, title string, sort int,
	public bool, parentId uint32, cover []string, ctx context.Context) (*CreateCollectionResponse, error) {

	fullUrl := *c.apiURL
	fullUrl.Path = path.Join(endpointCreateCollection)

	var collection createCollectionRequest

	if isRoot {
		collection = createCollectionRequest{
			View:   view,
			Title:  title,
			Sort:   sort,
			Public: public,
			Cover:  cover,
		}
	} else {
		collection = createCollectionRequest{
			View:     view,
			Title:    title,
			Sort:     sort,
			Public:   public,
			ParentId: parentId,
			Cover:    cover,
		}
	}

	request, err := c.newRequest(accessToken, http.MethodPost, fullUrl, collection, ctx)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	result := new(CreateCollectionResponse)
	err = parseResponse(response, 200, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// CreateSimpleRaindrop creates new simple unsorted Raindrop
// Reference: https://developer.raindrop.io/v1/raindrops/single#create-raindrop
func (c *Client) CreateSimpleRaindrop(accessToken string, link string, ctx context.Context) (*SingleRaindropResponse, error) {
	fullUrl := *c.apiURL
	fullUrl.Path = path.Join(endpointRaindrop)

	resp, _ := http.Get(link)
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Printf("Can't close response's Body in CreateSimpleRaindrop: %v", err)
		}
	}()

	title := ""
	if val, ok := GetHtmlTitle(resp.Body); ok {
		title = val
	} else {
		title = "Fail to get HTML title"
	}

	raindrop := Raindrop{
		RaindropUserInfo: RaindropUserInfo{
			Title: title,
			Link:  link,
		},
	}

	request, err := c.newRequest(accessToken, http.MethodPost, fullUrl, raindrop, ctx)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	result := new(SingleRaindropResponse)
	err = parseResponse(response, 200, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetRaindrops call get raindrops API.
// Reference: https://developer.raindrop.io/v1/raindrops/multiple#get-raindrops
func (c *Client) GetRaindrops(accessToken string, collectionID string, perpage int, ctx context.Context) (*MultiRaindropsResponse, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointRaindrops, collectionID)

	req, err := c.newRequest(accessToken, http.MethodGet, u, nil, ctx)
	if err != nil {
		return nil, err
	}

	query := req.URL.Query()
	query.Add("perpage", fmt.Sprint(perpage))
	req.URL.RawQuery = query.Encode()

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	r := new(MultiRaindropsResponse)
	if err := parseResponse(response, 200, &r); err != nil {
		return nil, err
	}

	return r, nil
}

func (c *Client) GetRaindrop(accessToken string, rId uint32, ctx context.Context) (*SingleRaindropResponse, error) {

	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointRaindrop, strconv.FormatUint(uint64(rId), 10))

	req, err := c.newRequest(accessToken, http.MethodGet, u, nil, ctx)
	if err != nil {
		return nil, err
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	r := new(SingleRaindropResponse)
	if err := parseResponse(response, 200, &r); err != nil {
		return nil, err
	}

	return r, nil
}

// GetTags calls Get tags API.
// Reference: https://developer.raindrop.io/v1/tags#get-tags
func (c *Client) GetTags(accessToken string, ctx context.Context) (*Tags, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointTags)
	request, err := c.newRequest(accessToken, http.MethodGet, u, nil, ctx)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	r := new(Tags)
	if err := parseResponse(response, 200, &r); err != nil {
		return nil, err
	}

	return r, nil
}

// GetTaggedRaindrops finds raindrops with exact tags.
// This function calls Get raindrops API with collectionID=0 and specify given tag as a search parameter.
//
// Reference: https://developer.raindrop.io/v1/raindrops/multiple#search-parameter
func (c *Client) GetTaggedRaindrops(accessToken string, tag string, ctx context.Context) (*MultiRaindropsResponse, error) {
	u := *c.apiURL
	u.Path = path.Join(c.apiURL.Path, endpointRaindrops+"0")
	request, err := c.newRequest(accessToken, http.MethodGet, u, nil, ctx)
	if err != nil {
		return nil, err
	}

	params := request.URL.Query()
	searchParameter := createSingleSearchParameter("tag", tag)
	params.Add("search", searchParameter)
	request.URL.RawQuery = params.Encode()

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	r := new(MultiRaindropsResponse)
	if err := parseResponse(response, 200, &r); err != nil {
		return nil, err
	}

	return r, nil
}

// GetAuthorizationURL returns URL for UserRef to authorize app
func (c *Client) GetAuthorizationURL() (url.URL, error) {
	u := c.authURL
	uri := fmt.Sprintf(authorizeUri, c.clientId, c.redirectUri)
	u.Path = path.Join(uri)
	return *u, nil
}

// GetAccessToken exchanges UserRef's authorization code to access token
// Reference: https://developer.raindrop.io/v1/authentication/token#step-3-the-token-exchange
func (c *Client) GetAccessToken(userCode string, ctx context.Context) (*AccessTokenResponse, error) {
	fullUrl := *c.authURL
	fullUrl.Path = path.Join(endpointAccessToken)

	body := accessTokenRequest{
		Code:         userCode,
		ClientID:     c.clientId,
		ClientSecret: c.clientSecret,
		RedirectUri:  c.redirectUri,
		GrantType:    "authorization_code",
	}

	request, err := c.newRequest("", http.MethodPost, fullUrl, body, ctx)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	result := new(AccessTokenResponse)
	err = parseResponse(response, 200, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// RefreshAccessToken refreshes expired token
// Reference: https://developer.raindrop.io/v1/authentication/token#the-access-token-refresh
func (c *Client) RefreshAccessToken(refreshToken string, ctx context.Context) (*AccessTokenResponse, error) {
	fullUrl := *c.authURL
	fullUrl.Path = path.Join(endpointAccessToken)

	body := refreshTokenRequest{
		ClientId:     c.clientId,
		ClientSecret: c.clientSecret,
		GrantType:    "authorization_code",
		RefreshToken: refreshToken,
	}

	request, err := c.newRequest("", http.MethodPost, fullUrl, body, ctx)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	result := new(AccessTokenResponse)
	err = parseResponse(response, 200, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetAuthorizationCodeHandler handles redirect request from raindrop's authorization page
func (c *Client) GetAuthorizationCodeHandler(w http.ResponseWriter, r *http.Request) {
	code, err := c.GetAuthorizationCode(r)
	if err != nil {
		fmt.Println(err)
	}

	_, err = fmt.Fprintf(w, "<h1>You've been authorized</h1><p>%s</p>", code)
	if err != nil {
		fmt.Println(err)
	}
	c.ClientCode = code
}

// GetAuthorizationCode returns authorization code or an error from raindrop's
// redirect request
// Reference: https://developer.raindrop.io/v1/authentication/token#step-2-the-redirection-to-your-application-site
func (c *Client) GetAuthorizationCode(r *http.Request) (string, error) {
	code := r.URL.Query().Get("code")
	authErr := r.URL.Query().Get("error")
	if code == "" && authErr != "" {
		return "", errors.New("Can't get authorization code: " + authErr)
	} else if code == "" {
		return "", errors.New("Can't get authorization code: " + strconv.Itoa(r.Response.StatusCode))
	}

	return code, nil
}

func createSingleSearchParameter(k, v string) string {
	return fmt.Sprintf(`[{"key":"%s","val":"%s"}]`, k, v)
}

func (c *Client) newRequest(accessToken string, httpMethod string, fullUrl url.URL,
	body interface{}, ctx context.Context) (*http.Request, error) {

	u, err := url.QueryUnescape(fullUrl.String())
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	if body != nil {
		err := json.NewEncoder(&b).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	var req *http.Request
	if ctx != nil {
		req, err = http.NewRequestWithContext(ctx, httpMethod, u, &b)
		if err != nil {
			return nil, err
		}
	} else {
		req, err = http.NewRequest(httpMethod, u, &b)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Add("Content-Type", "application/json")

	if accessToken != "" {
		bearerToken := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Add("Authorization", bearerToken)
	}

	return req, nil
}

func parseResponse(response *http.Response, expectedStatus int, clazz interface{}) error {
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != expectedStatus && response.StatusCode != 400 {
		err := fmt.Errorf("unexpected Status Code: %d", response.StatusCode)
		fmt.Printf("Can't parse response" + err.Error())
		return err
	}

	//var bodyCopy bytes.Buffer
	//tee := io.TeeReader(response.Body, &bodyCopy)
	//json.NewDecoder(tee).Decode(clazz)
	//fmt.Printf("%v\n", bodyCopy.String())
	//return nil

	return json.NewDecoder(response.Body).Decode(clazz)
}

// update api under this line

func (c *Client) CreateRaindrop(accessToken string, obj *RaindropUserInfo, ctx context.Context) (*SingleRaindropResponse, error) {
	fullUrl := *c.apiURL
	fullUrl.Path = path.Join(endpointRaindrop)

	if obj == nil {
		return nil, errors.New("param is nil")
	}

	request, err := c.newRequest(accessToken, http.MethodPost, fullUrl, *obj, ctx)
	if err != nil {
		return nil, err
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	result := new(SingleRaindropResponse)
	err = parseResponse(response, 200, &result)
	if err != nil {
		return nil, err
	}

	return result, nil

}
