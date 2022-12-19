package docker

import (
	"github.com/docker/distribution/reference"
	"github.com/moby/buildkit/frontend/dockerfile/parser"

	//"reflect"
	"crypto/sha256"
	"crypto/sha512"

	"encoding/json"
	"fmt"
	"strings"

	"dockerfileparse/user/parser/babashka"
)

type Reference struct {
	Path   string `json:"path"`
	Domain string `json:"domain,omitempty"`
	Tag    string `json:"tag,omitempty"`
	Digest string `json:"digest,omitempty"`
}

type Error struct {
	Error string `json:"error"`
}

func parse_uri(s string) (Reference, error) {
	tag, domain, path, digest := "", "", "", ""

	sha256.New()
	sha512.New()

	ref, err := reference.Parse(s)
	if err != nil {
		return Reference{}, err
	}
	//fmt.Printf("%s\n", reflect.TypeOf(ref));

	if tagged, ok := ref.(reference.NamedTagged); ok {
		tag = tagged.Tag()
	}
	if named, ok := ref.(reference.Named); ok {
		domain = reference.Domain(named)
		path = reference.Path(named)
	}
	if digested, ok := ref.(reference.Canonical); ok {
		digest = digested.Digest().String()
	}
	//u, err := json.Marshal(Reference{Path: path, Domain: domain, Tag: tag, Digest: digest})
	return Reference{Path: path, Domain: domain, Tag: tag, Digest: digest}, err
}

func run_sbom_tool(tx chan string, image string) error {
	// TODO perhaps the tx channel returns valid edn strings and the error channel can just return Errors
	// first message on errors channel signals that the client should expect no more sbom data
	return nil
}

func generate_sbom(message *babashka.Message, s string) {
	tx_channel := make(chan string)

	go func() error {
		for {
			select {
			case tx := <-tx_channel:
				err := babashka.WriteNotDoneInvokeResponse(message, tx)
				if err != nil {
					babashka.WriteErrorResponse(message, err)
				}
			}
		}
	}()

	err := run_sbom_tool(tx_channel, s)
	if err != nil {
		babashka.WriteErrorResponse(message, err)
	} else {
		babashka.WriteInvokeResponse(message, "done")
	}
}

func ProcessMessage(message *babashka.Message) (any, error) {
	switch message.Op {
	case "describe":
		return &babashka.DescribeResponse{
			Format: "json",
			Namespaces: []babashka.Namespace{
				{
					Name: "pod.atomisthq.docker",
					Vars: []babashka.Var{
						{
							Name: "parse-image-name",
						},
						{
							Name: "parse-dockerfile",
						},
						{
							Name: "sbom",
							Code: `
(defn sbom
  ([image cb]
   (sbom cb {}))
  ([image cb opts]
   (babashka.pods/invoke
     "pod.atomisthq.docker"
     'pod.atomisthq.docker/-generate-sbom
     [image]
     {:handlers {:success (fn [event]
                            (cb (update event :type keyword)))
                 :error   (fn [{:keys [:ex-message :ex-data]}]
                            (binding [*out* *err*]
                              (println "ERROR:" ex-message)))
		 :done    (fn [] (println "Done"))}})))`,
						},
					},
				},
			},
		}, nil
	case "invoke":
		switch message.Var {
		case "pod.atomisthq.docker/parse-image-name":
			args := []string{}
			if err := json.Unmarshal([]byte(message.Args), &args); err != nil {
				return nil, err
			}

			return parse_uri(args[0])
		case "pod.atomisthq.docker/parse-dockerfile":
			args := []string{}
			if err := json.Unmarshal([]byte(message.Args), &args); err != nil {
				return nil, err
			}
			reader := strings.NewReader(args[0])
			return parser.Parse(reader)
		case "pod.atomisthq.docker/-generate-sbom":
			args := []string{}
			if err := json.Unmarshal([]byte(message.Args), &args); err != nil {
				return nil, err
			}
			generate_sbom(message, args[0])
			return nil, nil

		default:
			return nil, fmt.Errorf("Unknown var %s", message.Var)
		}
	default:
		return nil, fmt.Errorf("Unknown op %s", message.Op)
	}
}
