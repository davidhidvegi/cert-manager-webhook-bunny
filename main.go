package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/davidhidvegi/cert-manager-webhook-bunny/internal"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&bunnyDNSProviderSolver{},
	)
}

// These are the things required to interact with Bunny API, should be located
// in secret, referenced in config by it's name
type bunnyClientConfig struct {
	apiKey string
}

type bunnyDNSProviderSolver struct {
	client *kubernetes.Clientset
}

type bunnyDNSProviderConfig struct {
	// name of the secret which contains Bunny credentials
	SecretRef string `json:"secretRef"`
	// optional namespace for the secret
	SecretNamespace string `json:"secretNamespace"`
}

func (n *bunnyDNSProviderSolver) Name() string {
	return "bunny"
}

func (n *bunnyDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := n.getConfig(ch)
	if err != nil {
		return err
	}
	if err := addTxtRecord(cfg, ch.ResolvedFQDN, ch.Key); err != nil {
		return err
	}
	klog.Infof("successfully presented challenge for domain '%s'", ch.DNSName)
	return nil
}

func (n *bunnyDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := n.getConfig(ch)
	if err != nil {
		return err
	}
	if err := deleteTxtRecord(cfg, ch.ResolvedFQDN, ch.Key); err != nil {
		return err
	}
	klog.Infof("successfully cleaned up challenge for domain '%s'", ch.DNSName)
	return nil
}

func (n *bunnyDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	n.client = cl
	return nil
}

func (n *bunnyDNSProviderSolver) getConfig(ch *v1alpha1.ChallengeRequest) (*bunnyClientConfig, error) {
	var secretNs string
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	bunnyCfg := &bunnyClientConfig{}

	if cfg.SecretNamespace != "" {
		secretNs = cfg.SecretNamespace
	} else {
		secretNs = ch.ResourceNamespace
	}

	sec, err := n.client.CoreV1().Secrets(secretNs).Get(context.TODO(), cfg.SecretRef, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}

	bunnyCfg.apiKey, err = stringFromSecretData(&sec.Data, "api-key")
	if err != nil {
		return nil, fmt.Errorf("unable to get 'api-key' from secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}

	return bunnyCfg, nil
}

func addTxtRecord(cfg *bunnyClientConfig, resolvedFqdn string, key string) error {
	zone, host, getErr := getZoneAndHost(resolvedFqdn, cfg)
	if getErr != nil {
		return getErr
	}

	zoneID := fmt.Sprintf("%d", zone.Id)
	urlOfRecords := "https://api.bunny.net/dnszone/" + zoneID + "/records"

	payload := strings.NewReader("{\"Type\":3,\"Ttl\":120,\"Value\":\"" + key + "\",\"Name\":\"" + host + "\"}")

	putResBody, putResErr := callDnsApi(urlOfRecords, "PUT", payload, cfg)
	if putResErr != nil {
		return fmt.Errorf("Failed to create record: %v", putResErr)
	}

	record := internal.Record{}
	recordReadErr := json.Unmarshal(putResBody, &record)
	if recordReadErr != nil {
		return fmt.Errorf("Unable to unmarshal response: %v", recordReadErr)
	}
	return nil
}

func deleteTxtRecord(cfg *bunnyClientConfig, resolvedFqdn string, key string) error {
	zone, host, getErr := getZoneAndHost(resolvedFqdn, cfg)
	if getErr != nil {
		return getErr
	}

	for _, record := range zone.Records {
		if record.Value == key && record.Type == 3 && record.Name == host {
			urlOfRecords := "https://api.bunny.net/dnszone/" + fmt.Sprintf("%d", zone.Id) + "/records/" + fmt.Sprintf("%d", record.Id)
			_, deleteResErr := callDnsApi(urlOfRecords, "DELETE", nil, cfg)
			if deleteResErr != nil {
				return fmt.Errorf("Failed to delete record: %v", deleteResErr)
			}
			break
		}
	}
	return nil
}

func getZoneAndHost(resolvedFqdn string, cfg *bunnyClientConfig) (internal.Items, string, error) {
	return findZoneAndHost(resolvedFqdn, func(domain string) (internal.ZoneResponse, error) {
		return getZonesBySearch(domain, cfg)
	})
}

func findZoneAndHost(resolvedFqdn string, lookup func(string) (internal.ZoneResponse, error)) (internal.Items, string, error) {
	labels, err := splitResolvedFQDN(resolvedFqdn)
	if err != nil {
		return internal.Items{}, "", err
	}

	for i := 1; i <= len(labels)-2; i++ {
		domain := strings.Join(labels[i:], ".")
		zones, lookupErr := lookup(domain)
		if lookupErr != nil {
			return internal.Items{}, "", fmt.Errorf("failed to request zones for %q: %v", domain, lookupErr)
		}
		for _, zone := range zones.Items {
			if strings.EqualFold(strings.TrimSuffix(zone.Domain, "."), domain) {
				return zone, strings.Join(labels[:i], "."), nil
			}
		}
	}

	return internal.Items{}, "", fmt.Errorf("unable to find a matching Bunny zone for resolved FQDN %q", resolvedFqdn)
}

func splitResolvedFQDN(resolvedFqdn string) ([]string, error) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(resolvedFqdn), ".")
	labels := strings.Split(trimmed, ".")
	if len(labels) < 3 {
		return nil, fmt.Errorf("unable to parse host/domain out of resolved FQDN %q", resolvedFqdn)
	}
	return labels, nil
}

func getZonesBySearch(domain string, cfg *bunnyClientConfig) (internal.ZoneResponse, error) {
	urlOfDnsZones := "https://api.bunny.net/dnszone?page=1&perPage=1000&search=" + domain

	getResBody, getResErr := callDnsApi(urlOfDnsZones, "GET", nil, cfg)
	if getResErr != nil {
		return internal.ZoneResponse{}, fmt.Errorf("Failed to request zones: %v", getResErr)
	}

	zones := internal.ZoneResponse{}
	zonesReadErr := json.Unmarshal(getResBody, &zones)
	if zonesReadErr != nil {
		return internal.ZoneResponse{}, fmt.Errorf("Unable to unmarshal response: %v", zonesReadErr)
	}
	return zones, nil
}

func callDnsApi(url, method string, body io.Reader, cfg *bunnyClientConfig) ([]byte, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to execute request %v", err)
	}
	req.Header.Add("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Set("AccessKey", cfg.apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			klog.Fatal(err)
		}
	}()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent {
		return respBody, nil
	}

	text := "Error calling API status:" + resp.Status + " url: " + url + " method: " + method
	klog.Error(text)
	return nil, errors.New(text)
}

func stringFromSecretData(secretData *map[string][]byte, key string) (string, error) {
	data, ok := (*secretData)[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret data", key)
	}
	return string(data), nil
}

func loadConfig(cfgJSON *extapi.JSON) (bunnyDNSProviderConfig, error) {
	cfg := bunnyDNSProviderConfig{}

	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}
