package kubeApiProxy

import (
  "github.com/google/nftables"
  "time"
  "log"
)

func Reconcile(kubeAPIExternalIP string, kubeAPIInternalIP string, kubeAPIExternalPort uint ,kubeAPIInternalPort uint, syncPeriod int64) {
   var cacheSnapshot map[string]RuleSnapshot
   for i := range baseRules {
   	switch baseRules[i].ruleType {
   	case "filter":
   		baseRules[i].originalIP =  IPToBytes(kubeAPIInternalIP)
   		baseRules[i].originalPort = intToBytes(kubeAPIInternalPort) 
   	case "nat":
   		baseRules[i].modifiedIP = IPToBytes(kubeAPIExternalIP) 
   		baseRules[i].modifiedPort = intToBytes(kubeAPIExternalPort)
   	}
   }
   c := &nftables.Conn{}
   ticker := time.NewTicker(time.Duration(syncPeriod) * time.Second)
   log.Println("Starting Kube Api Proxy")
   log.Printf("Redirecting Connection to api from %s on port %d to %s on port %d", kubeAPIInternalIP, kubeAPIInternalPort, kubeAPIExternalIP, kubeAPIExternalPort)

   defer ticker.Stop()
   for {
   	select {
           case <-ticker.C:
             createTable(c, natTable)
             for _ , chain := range baseChains {
                 createChain(c, chain)
             }
	     updateCache(c, baseChains, &cacheSnapshot)
             for _ , rule := range baseRules {
                 createRule(c,&rule,&cacheSnapshot)
             }
   	}
   }
}
