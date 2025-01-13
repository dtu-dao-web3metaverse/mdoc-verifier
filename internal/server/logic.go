package server

import (
	"crypto/sha256"

	"github.com/kokukuma/mdoc-verifier/decrypter"
	"github.com/kokukuma/mdoc-verifier/decrypter/openid4vp"
	doc "github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/session_transcript"
)

type IdentityRequest struct {
	Selector        doc.Selector `json:"selector"`
	Nonce           string       `json:"nonce"`
	ReaderPublicKey string       `json:"readerPublicKey"`
}

func createIDReq(req GetRequest, session *Session) interface{} {
	var idReq interface{}
	switch req.Protocol {
	case "preview":
		// MEMO: previewが生き残るのかどうか不明.
		// エージさんのブログではopenid4vpだけしか言われてなかったし、消えそうな気はする
		idReq = &IdentityRequest{
			Selector:        RequiredElements.Selector()[0], // Identity Credential API only accept single selector ... ?
			Nonce:           session.Nonce.String(),
			ReaderPublicKey: b64.EncodeToString(session.PrivateKey.PublicKey().Bytes()),
		}
	case "openid4vp":
		idReq = &openid4vp.AuthorizationRequest{
			ClientID:               "digital-credentials.dev",
			ClientIDScheme:         "web-origin",
			ResponseType:           "vp_token",
			Nonce:                  session.Nonce.String(),
			PresentationDefinition: RequiredElements.PresentationDefinition("mDL-request-demo"),
		}
	case "apple":
		// MEMO: Appleは実質Nonceだけだからそれほど気にしてないと言えばない.
		idReq = &IdentityRequest{
			Nonce: session.Nonce.String(),
		}
	}
	return idReq
}

// TODO: SessionTranscriptの作成は、一つのpackageにまとめた方がいいか？
func getSessionTranscript(req VerifyRequest, session *Session) ([]byte, error) {
	var sessTrans []byte
	var err error

	switch req.Protocol {
	case "openid4vp":
		// package nameはclientから取得するようにするか？
		hash := sha256.Sum256([]byte("digital-credentials.dev"))
		sessTrans, err = session_transcript.AndroidHandoverV1(session.GetNonceByte(), "com.android.mdl.appreader", hash[:])
		if req.Origin != "" {
			sessTrans, err = session_transcript.BrowserHandoverV1(session.GetNonceByte(), req.Origin, hash[:])
		}
	case "preview":
		// package nameはclientから取得するようにするか？
		sessTrans, err = session_transcript.AndroidHandoverV1(session.GetNonceByte(), "com.android.mdl.appreader", session.GetPublicKeyHash())
		if req.Origin != "" {
			sessTrans, err = session_transcript.BrowserHandoverV1(session.GetNonceByte(), req.Origin, session.GetPublicKeyHash())
		}
	case "apple":
		sessTrans, err = session_transcript.AppleHandoverV1(merchantID, teamID, session.GetNonceByte(), session.GetPublicKeyHash())
	}
	if err != nil {
		return nil, err
	}
	return sessTrans, nil
}

func parseDeviceResponse(req VerifyRequest, session *Session, sessTrans []byte) (*mdoc.DeviceResponse, error) {
	var devResp *mdoc.DeviceResponse
	var err error

	switch req.Protocol {
	case "openid4vp":
		devResp, err = decrypter.OpenID4VP(req.Data)
	case "preview":
		devResp, err = decrypter.AndroidHPKE(req.Data, session.GetPrivateKey(), sessTrans)
	case "apple":
		// This base64URL encoding is not in any spec, just depends on a client implementation.
		decoded, err := b64.DecodeString(req.Data)
		if err != nil {
			return nil, err
		}
		devResp, err = decrypter.AppleHPKE(decoded, session.GetPrivateKey(), sessTrans)
	}
	if err != nil {
		return nil, err
	}
	return devResp, nil
}

func getVerifiedDoc(devResp *mdoc.DeviceResponse, docType doc.DocType, sessTrans []byte, options []mdoc.VerifierOption) (*mdoc.Document, error) {
	doc, err := devResp.GetDocument(docType)
	if err != nil {
		return nil, err
	}

	// set verifier options mainly because there is no legitimate wallet for now.
	if err := mdoc.NewVerifier(roots, options...).Verify(doc, sessTrans); err != nil {
		return nil, err
	}
	return &doc, nil
}
