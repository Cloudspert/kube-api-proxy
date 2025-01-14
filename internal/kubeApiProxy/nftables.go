package kubeApiProxy

import (
  "fmt"
  "log"
  "github.com/google/nftables"
  "github.com/google/nftables/expr"
  "crypto/sha256"
  "encoding/hex"
  "golang.org/x/sys/unix"
)

var (
natTable = &nftables.Table{Name: "nat", Family: nftables.TableFamilyIPv4,}

baseChains = map[string]*nftables.Chain{
  "PREROUTING":&nftables.Chain{Name: "PREROUTING", Table: natTable, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest,},
  "OUTPUT": &nftables.Chain{Name: "OUTPUT", Table: natTable, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest,},
  "CAAS-REDIRECT-API": &nftables.Chain{Name: "CAAS-REDIRECT-API",Table: natTable,},
  "CAAS-CUSTOM-RULES": &nftables.Chain{Name: "CAAS-CUSTOM-RULES",Table: natTable,},
  }

baseRules = []nftRule{
	{ruleType: "jump", jumpChain: "CAAS-CUSTOM-RULES", chain: baseChains["PREROUTING"], table: natTable, beforeChain: "KUBE-SERVICES"},
	{ruleType: "jump", jumpChain: "CAAS-CUSTOM-RULES", chain: baseChains["OUTPUT"], table: natTable, beforeChain: "KUBE-SERVICES"},
	{ruleType: "filter", table: natTable, chain: baseChains["CAAS-CUSTOM-RULES"], jumpChain: "CAAS-REDIRECT-API"},
	{ruleType: "nat", table: natTable, chain: baseChains["CAAS-REDIRECT-API"]},
}
cacheSnapshot = map[string]RuleSnapshot{}
)

func createTable(c *nftables.Conn, tableName string) (*nftables.Table) {
  tables, err := c.ListTables()
  if err != nil {
     fmt.Errorf("could not list chains: %v", err)
  }
  for _ , table := range tables {
     if table.Name == tableName {
        return table 
     }
  }
  table := c.AddTable(&nftables.Table{
                             Name:   tableName,
                             Family: nftables.TableFamilyIPv4,
		     })
  c.Flush()
  return table 
} 


func getChain(c *nftables.Conn, chainName string)(*nftables.Chain) {
  chains, _ := c.ListChains()
  for _, chain := range chains {
  	if chain.Name == chainName {
 	   return chain
  	}
  }
  return nil
}

func createChain(c *nftables.Conn, dstChain *nftables.Chain) (*nftables.Chain) {
  exitingChain := getChain(c, dstChain.Name) 
  if (exitingChain != nil) && (dstChain.Type != "" || dstChain.Hooknum != nil || dstChain.Priority != nil) {
     if (dstChain.Type == exitingChain.Type) && (*dstChain.Hooknum == *exitingChain.Hooknum) && (*dstChain.Priority == *exitingChain.Priority) { 
	return exitingChain
     } else if exitingChain != nil {
      c.DelChain(exitingChain)
      c.Flush()
     }
  }
  c.AddChain(dstChain)
  c.Flush()
  return dstChain
}

func getRuleOrder(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, targetChain string) uint64 {
   rules, _ := c.GetRules(table,chain)
   for _ , rule := range rules {
      for _ , exp := range rule.Exprs {
         verdict, ok := exp.(*expr.Verdict) 
	 if ok && verdict.Chain == targetChain {
	    return rule.Position
	 }
      }
   }
   return uint64(0)
}

func calculateRuleHash(rule *nftables.Rule) string {
  var ruleData string
  for _, e := range rule.Exprs {
    switch e := e.(type) {
      case *expr.Payload:
      	ruleData += fmt.Sprintf("PayloadBase:%d Offset:%d Len:%d ", e.Base, e.Offset, e.Len)
      case *expr.Cmp:
      	ruleData += fmt.Sprintf("CmpOp:%d Data:%x ", e.Op, e.Data)
      case *expr.Verdict:
        ruleData += fmt.Sprintf("VerdictKind:%d Chain:%s", e.Kind, e.Chain)
      case *expr.Immediate:
      	ruleData += fmt.Sprintf("ImmediateRegister:%d Data:%x ", e.Register, e.Data)
      case *expr.NAT:
      	ruleData += fmt.Sprintf("NATType:%d Family:%d RegAddr:%d RegPort:%d ", e.Type, e.Family, e.RegAddrMin, e.RegProtoMin)
      case *expr.Meta:
      	ruleData += fmt.Sprintf("MetaKey:%d Data:%x ", e.Key, e.Register)
      default:
    	ruleData += fmt.Sprintf("UnknownExpr:%T ", e)
	}
  }
  hash := sha256.Sum256([]byte(ruleData))
  return hex.EncodeToString(hash[:])
}

func calculateHashChain(c *nftables.Conn, chain *nftables.Chain) RuleSnapshot { 
   var hashs []string
   rules, err := c.GetRules(chain.Table,chain)
   if err != nil {
        fmt.Errorf("could not list chains: %v", err)
   }
   for _ , rule  := range rules {
   	hash := calculateRuleHash(rule)
   	hashs = append(hashs, hash)
   }
   return RuleSnapshot{Chain: chain, Hashs: hashs}
}


func getRule(c *nftables.Conn, rule *nftables.Rule) *nftables.Rule { 
   rules, err := c.GetRules(rule.Table,rule.Chain)
   if err != nil {
        fmt.Errorf("could not list chains: %v", err)
   }
   for _ , r  := range rules {
   	if  calculateRuleHash(rule) == calculateRuleHash(r) {
    	    return r
        }
   }
   return rule 
}


func updateCache(c *nftables.Conn, chains map[string]*nftables.Chain, cache *map[string]RuleSnapshot) {
    snapshotChains := make(map[string]RuleSnapshot)
    for key, chain := range chains {
        snapshotChain := calculateHashChain(c, chain)
        snapshotChains[key] = snapshotChain
    }
    *cache = snapshotChains
    return
}

func checkRules(c *nftables.Conn, ruleObj *nftables.Rule, rule *nftRule, cache *map[string]RuleSnapshot) bool {
    ruleSnapshot := calculateRuleHash(ruleObj)
    if chainSnapshot, exists := (*cache)[ruleObj.Chain.Name]; exists {
        hashExists := false
        for _, h := range chainSnapshot.Hashs {
            if h == ruleSnapshot {
                hashExists = true
                break
            }
        }
        if hashExists {
            if rule.beforeChain != "" {
                targetRulePosition := getRuleOrder(c, rule.table, rule.chain, rule.beforeChain)
		rulePosition := getRuleOrder(c, rule.table, rule.chain, rule.jumpChain)
                if rulePosition > targetRulePosition {
		    log.Printf("Found rule with name %s before our rule, we need to change rule order",rule.beforeChain  )
                    c.DelRule(getRule(c, ruleObj))
                    c.Flush()
                    return true
                }
            }
            return false
        }
    }
    return true
}

func createRule(c *nftables.Conn, rule *nftRule, cache *map[string]RuleSnapshot) (*nftables.Rule) {
   var r *nftables.Rule
   switch rule.ruleType {
      case "filter":
           r = &nftables.Rule{
        	        Table: rule.table,
        	        Chain: rule.chain,
                        Exprs: []expr.Any{
                                   &expr.Meta{
                                   	Key:      expr.MetaKeyL4PROTO,
                                   	Register: 2,
                                   },
                                   &expr.Cmp{
                                   	Op:       expr.CmpOpEq,
                                   	Register: 2,
                                   	Data:     []byte{unix.IPPROTO_TCP}, 
                                   },
                                   &expr.Payload{
                                   	DestRegister: 1,
                                   	Base:         expr.PayloadBaseNetworkHeader,
                                   	Offset:       16,
                                   	Len:          4,
                                   },
                                   &expr.Cmp{
                                   	Op:       expr.CmpOpEq,
                                   	Register: 1,
                                   	Data:     rule.originalIP,
                                   },
                                   &expr.Payload{
                                   	DestRegister: 1,
                                   	Base:         expr.PayloadBaseTransportHeader,
                                   	Offset:       2,
                                   	Len:          2,
                                   },
                                   &expr.Cmp{
                                   	Op:       expr.CmpOpEq,
                                   	Register: 1,
                                   	Data:     rule.originalPort,
                                   },
                                   &expr.Verdict{
                                   	Kind: expr.VerdictJump,
                                   	Chain: rule.jumpChain,},},}
      case "jump":
           r = &nftables.Rule{
      	        Table: rule.table,
      	        Chain: rule.chain,
                      Exprs: []expr.Any{
                                &expr.Verdict{
                                 	Kind: expr.VerdictJump,
                                 	Chain: rule.jumpChain,},}}
      case "nat":
          r = &nftables.Rule{
             	Table: rule.table,
             	Chain: rule.chain,
             	Exprs: []expr.Any{
                            &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
                            &expr.Cmp{
                            	Op:       expr.CmpOpEq,
                            	Register: 1,
                            	Data:     []byte{unix.IPPROTO_TCP},
                            },
            
             		&expr.Immediate{
             			Register: 1,
             			Data:    rule.modifiedIP, 
             		},
                 		&expr.Immediate{
                 			Register: 2,
                 			Data:  rule.modifiedPort, 
                 		},

             		&expr.NAT{
             			Type:       expr.NATTypeDestNAT,
             			Family:     unix.NFPROTO_IPV4,
             			RegAddrMin: 1,
             			RegProtoMin: 2,
             		},},}
  }
  if checkRules(c,r,rule,cache) { 
     if (rule.beforeChain != "") && (getChain(c,rule.beforeChain) != nil) {
        insertOrder := getRuleOrder(c, rule.table, rule.chain, rule.beforeChain)
	r.Position = insertOrder 
        c.InsertRule(r)
	log.Println("Rule order successfully")
     } else{ c.AddRule(r)}
     c.Flush()
  }

  return r
}
