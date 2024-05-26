package handler

import (
	"fmt"
	"github.com/GeertJohan/yubigo"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/nmcclain/ldap"
	"github.com/rs/zerolog"
	"net"
)

func NewDumpHandler(opts ...Option) Handler {
	options := newOptions(opts...)
	handler := dumpHandler{
		backend:     options.Backend,
		log:         options.Logger,
		cfg:         options.Config,
		yubikeyAuth: options.YubiAuth,
		ldohelper:   options.LDAPHelper,
	}
	return handler
}

type dumpHandler struct {
	backend     config.Backend
	log         *zerolog.Logger
	cfg         *config.Config
	yubikeyAuth *yubigo.YubiAuth
	ldohelper   LDAPOpsHelper
}

func (h dumpHandler) GetBackend() config.Backend {
	fmt.Printf("GetBackend()\n")
	return h.backend
}

func (h dumpHandler) GetLog() *zerolog.Logger {
	fmt.Printf("GetLog()\n")
	return h.log
}

func (h dumpHandler) GetCfg() *config.Config {
	fmt.Printf("GetCfg()\n")
	return h.cfg
}

func (h dumpHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	fmt.Printf("GetYubikeyAuth()\n")
	return h.yubikeyAuth
}

var _ Handler = &dumpHandler{}
var _ LDAPOpsHandler = &dumpHandler{}

func (h dumpHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	fmt.Printf("Bind()\n")
	return h.ldohelper.Bind(h, bindDN, bindSimplePw, conn)
}

func (h dumpHandler) Search(boundDN string, req ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	fmt.Printf("Search()\n")
	return h.ldohelper.Search(h, boundDN, req, conn)
}

func (h dumpHandler) Close(boundDN string, conn net.Conn) error {
	h.log.Info().Str("handler", "dump").Msg(fmt.Sprintf("Close(boundDN:'%s')", boundDN))
	return nil
}

func (h dumpHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	fmt.Printf("Add()\n")
	h.log.Error().Msg("Add() function not implemented")
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h dumpHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	fmt.Printf("Modify()\n")
	h.log.Error().Msg("Modify() function not implemented")
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h dumpHandler) Delete(boundDN, deleteDN string, conn net.Conn) (ldap.LDAPResultCode, error) {
	fmt.Printf("Delete()\n")
	h.log.Error().Msg("Delete() function not implemented")
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (h dumpHandler) FindUser(userName string, searchByUPN bool) (bool, config.User, error) {
	fmt.Printf("FindUser(userName:'%s' searchByUPN:%v)\n", userName, searchByUPN)
	user := config.User{
		Name:         "serviceuser",
		Mail:         "serviceuser@example.com",
		UIDNumber:    5003,
		PassSHA256:   "652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0", // mysecret
		PrimaryGroup: 5502,
		Capabilities: []config.Capability{
			{Action: "search", Object: "*"},
		},
	}
	return true, user, nil
}

/*
[[users]]
name = "serviceuser"
mail = "serviceuser@example.com"
uidnumber = 5003
primarygroup = 5502
passsha256 = "652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0" # mysecret
[[users.capabilities]]
action = "search"
object = "*"
*/

func (h dumpHandler) FindGroup(groupName string) (bool, config.Group, error) {
	fmt.Printf("FindGroup(groupName:'%s')\n", groupName)
	group := config.Group{
		Name:      "svcaccts",
		GIDNumber: 5502,
	}
	return true, group, nil
}

/*
[[groups]]
name = "svcaccts"
gidnumber = 5502
*/

func (h dumpHandler) FindPosixAccounts(hierarchy string) (entrylist []*ldap.Entry, err error) {
	fmt.Printf("FindPosixAccounts(hierarchy:`%s')\n", hierarchy)
	entries := []*ldap.Entry{}
	return entries, nil
}

func (h dumpHandler) FindPosixGroups(hierarchy string) (entrylist []*ldap.Entry, err error) {
	fmt.Printf("FindPosixGroups(hierarchy:'%s')\n", hierarchy)
	asGroupOfUniqueNames := hierarchy == "ou=groups"
	entries := []*ldap.Entry{}
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: h.backend.GroupFormat, Values: []string{"superheros"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{"superheros"}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s", "superheros")}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "gidNumber", Values: []string{fmt.Sprintf("%d", 5501)}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "uniqueMember", Values: h.getGroupMemberDNs(5501)})
	if asGroupOfUniqueNames {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"groupOfUniqueNames", "top"}})
	} else {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: h.getGroupMemberIDs(5501)})
		attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup", "top"}})
	}
	dn := fmt.Sprintf("%s=%s,%s,%s", h.backend.GroupFormat, "superheros", hierarchy, h.backend.BaseDN)
	entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
	return entries, nil
}

func (h dumpHandler) getGroupMemberDNs(i int) []string {
	return []string{}
}

func (h dumpHandler) getGroupMemberIDs(i int) []string {
	return []string{}
}

/*
[[groups]]
name = "superheros"
gidnumber = 5501

[[groups]]
name = "svcaccts"
gidnumber = 5502

[[groups]]
name = "vpn"
gidnumber = 5503
includegroups = [ 5501 ]

*/
