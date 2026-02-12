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
natTable = &nftables.Table{Name: "CAAS", Family: nftables.TableFamilyIPv4,}

ChainPriorityCAAS  *nftables.ChainPriority = nftables.ChainPriorityRef(-130)

baseChains = map[string]*nftables.Chain{
  "PREROUTING":&nftables.Chain{Name: "PREROUTING", Table: natTable, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: ChainPriorityCAAS,},
  "OUTPUT": &nftables.Chain{Name: "OUTPUT", Table: natTable, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookOutput, Priority: ChainPriorityCAAS,},
  "CAAS-REDIRECT-API": &nftables.Chain{Name: "CAAS-REDIRECT-API",Table: natTable,},
  "CAAS-CUSTOM-RULES": &nftables.Chain{Name: "CAAS-CUSTOM-RULES",Table: natTable,},
}

baseRules = []nftRule{
	{ruleType: "jump", jumpChain: baseChains["CAAS-CUSTOM-RULES"], chain: baseChains["PREROUTING"], table: natTable},
	{ruleType: "jump", jumpChain: baseChains["CAAS-CUSTOM-RULES"], chain: baseChains["OUTPUT"], table: natTable},
	{ruleType: "filter", table: natTable, chain: baseChains["CAAS-CUSTOM-RULES"], jumpChain: baseChains["CAAS-REDIRECT-API"]},
	{ruleType: "nat", table: natTable, chain: baseChains["CAAS-REDIRECT-API"]},
}

cacheSnapshot = map[string]RuleSnapshot{}
)

func getTable(c *nftables.Conn, tableName string) (*nftables.Table) {
  tables, err := c.ListTablesOfFamily(nftables.TableFamilyIPv4)
  
  if err != nil {
     fmt.Errorf("Could not list tables: %v", err)
  }
  for _ , t := range tables {
     if t.Name == tableName {
        return t
     }
  }
  return nil
}

func createTable(c *nftables.Conn, t *nftables.Table) (*nftables.Table) {
  existingTable := getTable(c, t.Name)

  if existingTable != nil {
    return existingTable
  }

  log.Printf("Creating table with name: %s",t.Name)
  table := c.AddTable(t)
  if err := c.Flush(); err != nil {
      fmt.Errorf("Failed to create table %s: %v", t.Name, err)
      return nil 
  }

  return table 
} 

func getChain(c *nftables.Conn, ch *nftables.Chain)(*nftables.Chain) {
  chains, _ := c.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
  for _, chain := range chains {
  	if chain.Name == ch.Name && chain.Table.Name == ch.Table.Name {
 	   return chain
  	}
  }
  return nil
}

func createChain(c *nftables.Conn, ch *nftables.Chain) (*nftables.Chain) {
  exitingChain := getChain(c, ch) 
  if (exitingChain != nil){
    return exitingChain
  }
  log.Printf("Creating chain with name: %s", ch.Name)
  c.AddChain(ch)
  if err := c.Flush(); err != nil {
      fmt.Errorf("Failed to create chain %s: %v", ch.Name, err)
      return nil 
  }
  return ch
}

func getRuleOrder(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, targetChain *nftables.Chain) uint64 {
   rules, _ := c.GetRules(table,chain)
   for _ , rule := range rules {
      for _ , exp := range rule.Exprs {
         verdict, ok := exp.(*expr.Verdict) 
	 if ok && verdict.Chain == targetChain.Name {
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
            if rule.beforeChain != nil {
                targetRulePosition := getRuleOrder(c, rule.table, rule.chain, rule.beforeChain)
		rulePosition := getRuleOrder(c, rule.table, rule.chain, rule.jumpChain)
                if rulePosition > targetRulePosition {
		    log.Printf("Found rule with name %s before our rule, we need to change rule order",rule.beforeChain.Name  )
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
                                   	Chain: rule.jumpChain.Name,},},}
      case "jump":
           r = &nftables.Rule{
      	        Table: rule.table,
      	        Chain: rule.chain,
                      Exprs: []expr.Any{
                                &expr.Verdict{
                                 	Kind: expr.VerdictJump,
                                 	Chain: rule.jumpChain.Name,},}}
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
     if (rule.beforeChain != nil) && (getChain(c,rule.beforeChain) != nil) {
        insertOrder := getRuleOrder(c, rule.table, rule.chain, rule.beforeChain)
	r.Position = insertOrder 
        c.InsertRule(r)
	log.Println("Rule order successfully")
     } else{ c.AddRule(r)}
     c.Flush()
  }

  return r
}
