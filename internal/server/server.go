package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/kokukuma/mdoc-verifier/apple_hpke"
	"github.com/kokukuma/mdoc-verifier/credential_data"
	"github.com/kokukuma/mdoc-verifier/document"
	doc "github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/internal/cryptoroot"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/openid4vp"
	"github.com/kokukuma/mdoc-verifier/pkg/pki"
	"github.com/kokukuma/mdoc-verifier/preview_hpke"
)

var (
	roots *x509.CertPool
	b64   = base64.URLEncoding.WithPadding(base64.StdPadding)

	merchantID          = "PassKit_Identity_Test_Merchant_ID"
	teamID              = "PassKit_Identity_Test_Team_ID"
	applePrivateKeyPath = os.Getenv("APPLE_MERCHANT_ENCRYPTION_PRIVATE_KEY_PATH")
	serverDomain        = os.Getenv("SERVER_DOMAIN")
)

func NewServer() *Server {
	dir, err := filepath.Abs(filepath.Dir("."))
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}
	roots, err = pki.GetRootCertificates(filepath.Join(dir, "internal", "server", "pems"))
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}

	sigKey, certChain, err := cryptoroot.GenECDSAKeys()
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}

	encKey, _, err := cryptoroot.GenECDSAKeys()
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}
	return &Server{
		sessions:  NewSessions(),
		sigKey:    sigKey,
		encKey:    encKey,
		certChain: certChain,
	}
}

type Server struct {
	mu        sync.RWMutex
	sessions  *Sessions
	sigKey    *ecdsa.PrivateKey
	encKey    *ecdsa.PrivateKey
	certChain []string
}

type GetRequest struct {
	Protocol string `json:"protocol"`
}

type GetResponse struct {
	SessionID string      `json:"session_id"`
	Data      interface{} `json:"data"`
}

type VerifyRequest struct {
	SessionID string `json:"session_id"`
	Protocol  string `json:"protocol"`
	Data      string `json:"data"`
	Origin    string `json:"origin"`
}

type VerifyResponse struct {
	Elements []Element `json:"elements,omitempty"`
	Error    string    `json:"error,omitempty"`
}

type Element struct {
	NameSpace  document.NameSpace         `json:"namespace"`
	Identifier document.ElementIdentifier `json:"identifier"`
	Value      document.ElementValue      `json:"value"`
}

func (s *Server) GetIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := GetRequest{}
	if err := parseJSON(r, &req); err != nil {

		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}
	spew.Dump(req)

	var idReq interface{}
	var sessionData *SessionData
	var err error

	switch req.Protocol {
	case "preview":
		// ageOver21, _ := mdoc.AgeOver(21) // only 21 works now...why..
		// spew.Dump(ageOver21)
		idReq, sessionData, err = BeginIdentityRequest(
			WithFormat([]string{"mdoc"}),
			WithDocType("org.iso.18013.5.1.mDL"),
			AddField(doc.ISO1801351, doc.IsoFamilyName, false),
			AddField(doc.ISO1801351, doc.IsoGivenName, false),
			AddField(doc.ISO1801351, doc.IsoDocumentNumber, false),
			AddField(doc.ISO1801351, doc.IsoBirthDate, false),
			// preview_hpke.AddField(mdoc.IssueDate),
			// preview_hpke.AddField(mdoc.IssuingCountry),
			// preview_hpke.AddField(ageOver21),
		)
		if err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to get BeginIdentityRequest: preview: %v", err), http.StatusBadRequest)
			return
		}
	case "openid4vp":
		// TODO: optinoal function for openid4vp
		idReq, sessionData, err = BeginIdentityRequestOpenID4VP("digital-credentials.dev")
		if err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to get BeginIdentityRequest: openid4vp: %v", err), http.StatusBadRequest)
			return
		}
	case "apple":
		privKey, err := pki.LoadPrivateKey(applePrivateKeyPath)
		if err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to get BeginIdentityRequest: openid4vp: %v", err), http.StatusBadRequest)
			return
		}
		nonce, err := CreateNonce()
		if err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to get BeginIdentityRequest: apple: %v", err), http.StatusBadRequest)
			return
		}
		idReq = credential_data.IdentityRequest{
			Nonce: nonce.String(),
		}
		sessionData = &SessionData{
			Nonce:      nonce,
			PrivateKey: privKey,
		}
	}
	id, err := s.sessions.SaveIdentitySession(sessionData)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to SaveIdentitySession: %v", err), http.StatusBadRequest)
		return
	}

	spew.Dump(idReq)
	spew.Dump(sessionData)

	jsonResponse(w, GetResponse{
		SessionID: id,
		Data:      idReq,
	}, http.StatusOK)

	return
}

func (s *Server) VerifyIdentityResponse(w http.ResponseWriter, r *http.Request) {
	req := VerifyRequest{}
	if err := parseJSON(r, &req); err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parseJSON: %v", err), http.StatusBadRequest)
		return
	}

	session, err := s.sessions.GetIdentitySession(req.SessionID)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetIdentitySession: %v", err), http.StatusBadRequest)
		return
	}

	var devResp *mdoc.DeviceResponse
	var sessTrans []byte
	var skipVerification bool

	switch req.Protocol {
	case "openid4vp":
		vpData, err := openid4vp.ParseVPTokenResponse(req.Data)
		if err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to GetIdentitySession: %v", err), http.StatusBadRequest)
			return
		}
		devResp, sessTrans, err = openid4vp.ParseDeviceResponse(vpData, req.Origin, "digital-credentials.dev", session.GetNonceByte(), "browser")
	case "preview":
		devResp, sessTrans, err = preview_hpke.ParseDeviceResponse(req.Data, req.Origin, session.GetPrivateKey(), session.GetNonceByte())
	case "apple":
		// Appleのシミュレータが返す値が不完全で検証できないので一旦スキップ
		// * devieSignature不完全な状態で返してくる。
		// * issureAuthのheaderも入ってない
		skipVerification = true
		decoded, err := b64.DecodeString(req.Data)
		if err != nil {
			// return nil, nil, fmt.Errorf("Error decoding Base64URL string: %v", err)
			jsonErrorResponse(w, fmt.Errorf("failed to GetIdentitySession: %v", err), http.StatusBadRequest)
			return
		}
		devResp, sessTrans, err = apple_hpke.ParseDeviceResponse(decoded, merchantID, teamID, session.GetPrivateKey(), session.GetNonceByte())
	}
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to ParseDeviceResponse: %v", err), http.StatusBadRequest)
		return
	}
	spew.Dump(devResp)

	var resp VerifyResponse
	for _, doc := range devResp.Documents {
		if !skipVerification {
			if err := mdoc.Verify(doc, sessTrans, roots, true, false); err != nil {
				jsonErrorResponse(w, fmt.Errorf("failed to verify mdoc: %v", err), http.StatusBadRequest)
				return
			}
		}

		itemsmap, err := doc.IssuerSigned.IssuerSignedItems()
		if err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to get IssuerSignedItems: %v", err), http.StatusBadRequest)
			return
		}

		for ns, items := range itemsmap {
			for _, item := range items {
				resp.Elements = append(resp.Elements, Element{
					NameSpace:  ns,
					Identifier: item.ElementIdentifier,
					Value:      item.ElementValue,
				})
			}
		}
	}

	jsonResponse(w, resp, http.StatusOK)
}

func parseJSON(r *http.Request, v interface{}) error {
	if r == nil || r.Body == nil {
		return errors.New("No request given")
	}

	defer r.Body.Close()
	defer io.Copy(io.Discard, r.Body)

	err := json.NewDecoder(r.Body).Decode(v)
	if err != nil {
		return err
	}
	return nil
}

func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	spew.Dump(dj)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

func jsonErrorResponse(w http.ResponseWriter, e error, c int) {
	var resp VerifyResponse
	resp.Error = e.Error()
	dj, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	spew.Dump(dj)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}
