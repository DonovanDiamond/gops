package gops

import "strings"

type ADUser struct {
	SamAccountName string
	Enabled        bool

	GivenName string
	Initials  string
	Surname   string
	Name      string

	MemberOf     []string
	PrimaryGroup string

	SID struct {
		Value string
	}
	UserPrincipalName string
	DistinguishedName string
	ObjectClass       string
	ObjectGuid        string
	PropertyNames     []string
	ObjectGUID        string

	CannotChangePassword bool
	LockedOut            bool
	PasswordExpired      bool
	PasswordNeverExpires bool
	PasswordNotRequired  bool

	Created                string // Date()
	Modified               string // Date()
	LastLogonDate          string // Date()
	LastBadPasswordAttempt string // Date()
	PasswordLastSet        string // Date()

	EmployeeID   string
	Office       string
	Title        string
	Department   string
	Organization string
	Description  string
	EmailAddress string
	MobilePhone  string
	OtherName    string
}

func (u *ADUser) MemberOfShortNames() (groups []string) {
	groups = []string{}
	for _, g := range u.MemberOf {
		groups = append(groups, u.GetShortGroupName(g))
	}
	return
}

func (u *ADUser) GetShortGroupName(longName string) string {
	longName = strings.Split(longName, ",")[0]
	longName = strings.ReplaceAll(longName, "CN=", "")
	return longName
}

type ADGroup struct {
	GroupScope     int
	GroupCategory  int
	SamAccountName string
	SID            struct {
		Value string
	}
	DistinguishedName string
	Name              string
	ObjectClass       string
	ObjectGuid        string
	PropertyCount     int
	ObjectGUID        string
	Members           []string
}

func (g *ADGroup) MembersShortNames() (members []string) {
	members = []string{}
	for _, m := range g.Members {
		m = strings.Split(m, ",")[0]
		m = strings.ReplaceAll(m, "CN=", "")
		members = append(members, m)
	}
	return
}
