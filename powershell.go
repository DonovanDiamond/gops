package gops

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// GetADUser runs Get-ADUser with the filter:
//
// "samAccountName -like 'username'"
//
// If no users are found, an error and empty ADUser is returned.
//
// Otherwise, the first or only user is returned.
func GetADUser(username string) (ADUser, error) {
	users, err := GetADUsers("samAccountName", "-like", fmt.Sprintf("'%s'", username))
	if err != nil {
		return ADUser{}, fmt.Errorf("failed to get user: %w", err)
	}
	if len(users) == 0 {
		return ADUser{}, fmt.Errorf("failed to find username '%s'", username)
	}
	return users[0], nil
}

// GetADUsers runs Get-ADUser with each filter in filters joined by a space.
//
// If no filters are specified, the filter is set to: "*"
func GetADUsers(filters ...string) ([]ADUser, error) {
	filterString := "*"
	if len(filters) != 0 {
		filterString = strings.Join(filters, " ")
	}
	cmd := `Get-ADUser -Filter "` + filterString + `" -Properties MemberOf,Initials,CannotChangePassword,Created,Department,Description,EmailAddress,EmployeeID,LastBadPasswordAttempt,LastLogonDate,LockedOut,MobilePhone,Modified,Office,Organization,OtherName,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,PrimaryGroup,Title | ConvertTo-Json`
	out, err := PSCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("command '%s' returned: %w", cmd, err)
	}
	var users []ADUser
	if err := json.Unmarshal(out, &users); err != nil {
		// sometimes it returns an object and not an array
		var user ADUser
		if err := json.Unmarshal(out, &user); err != nil {
			return nil, fmt.Errorf("failed to unmarshal json: %w", err)
		}
		users = []ADUser{user}
	}
	return users, nil
}

type NewADUserRequiredParams struct {
	FQDN           string
	SamAccountName string
	Enabled        bool

	GivenName string
	Initials  string
	Surname   string
	Name      string

	Password string
}

type NewADUserOptionalParams struct {
	CannotChangePassword  bool
	ChangePasswordAtLogon bool
	PasswordNeverExpires  bool

	EmployeeID   string
	Office       string
	Title        string
	Department   string
	Organization string
	Description  string
	EmailAddress string
	MobilePhone  string
	OtherName    string

	Path string
}

// NewADUser runs New-ADUser with specified params.
//
// required params are needed for the command to succeed.
//
// optional params are optional.
func NewADUser(required NewADUserRequiredParams, optional NewADUserOptionalParams) error {
	cmd := fmt.Sprintf(`New-ADUser -UserPrincipalName %s@%s -SamAccountName %s -GivenName '%s' -Surname '%s' -Name '%s' -DisplayName '%s' -AccountPassword $(ConvertTo-SecureString -String '%s' -AsPlainText -Force) -Enabled $true`, required.SamAccountName, required.FQDN, required.SamAccountName, required.GivenName, required.Surname, required.Name, required.Name, required.Password)

	if optional.CannotChangePassword {
		cmd += " -CannotChangePassword $true"
	}
	if optional.ChangePasswordAtLogon {
		cmd += " -ChangePasswordAtLogon $true"
	}
	if optional.PasswordNeverExpires {
		cmd += " -PasswordNeverExpires $true"
	}
	if optional.EmployeeID != "" {
		cmd += fmt.Sprintf(" -EmployeeID '%s'", optional.EmployeeID)
	}
	if optional.Office != "" {
		cmd += fmt.Sprintf(" -Office '%s'", optional.Office)
	}
	if optional.Title != "" {
		cmd += fmt.Sprintf(" -Title '%s'", optional.Title)
	}
	if optional.Department != "" {
		cmd += fmt.Sprintf(" -Department '%s'", optional.Department)
	}
	if optional.Organization != "" {
		cmd += fmt.Sprintf(" -Organization '%s'", optional.Organization)
	}
	if optional.Description != "" {
		cmd += fmt.Sprintf(" -Description '%s'", optional.Description)
	}
	if optional.EmailAddress != "" {
		cmd += fmt.Sprintf(" -EmailAddress '%s'", optional.EmailAddress)
	}
	if optional.MobilePhone != "" {
		cmd += fmt.Sprintf(" -MobilePhone '%s'", optional.MobilePhone)
	}
	if optional.OtherName != "" {
		cmd += fmt.Sprintf(" -OtherName '%s'", optional.OtherName)
	}
	if optional.Path != "" {
		cmd += fmt.Sprintf(" -Path '%s'", optional.Path)
	}

	out, err := PSCommand(cmd)
	if err != nil {
		return fmt.Errorf("command '%s' returned: %w: %s", cmd, err, out)
	}

	return nil
}

// GetADGroups runs Get-ADGroup with each filter in filters joined by a space.
//
// If no filters are specified, the filter is set to: "*"
func GetADGroups(filters ...string) ([]ADGroup, error) {
	filterString := "*"
	if len(filters) != 0 {
		filterString = strings.Join(filters, " ")
	}
	cmd := `Get-ADGroup -Filter "` + filterString + `" -Properties Members | ConvertTo-Json`
	out, err := PSCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("command '%s' returned: %w", cmd, err)
	}
	var groups []ADGroup
	if err := json.Unmarshal(out, &groups); err != nil {
		// sometimes it returns an object and not an array
		var group ADGroup
		if err := json.Unmarshal(out, &group); err != nil {
			return nil, fmt.Errorf("failed to unmarshal json: %w", err)
		}
		groups = []ADGroup{group}
	}
	return groups, nil
}

// ResetADUserPassword resets the user's password using the net user command.
func ResetADUserPassword(username string, password string, active bool, mustChange bool) error {
	activeArg := "/active:"
	if active {
		activeArg += "yes"
	} else {
		activeArg += "no"
	}
	mustChangeArg := "/logonpasswordchg:"
	if mustChange {
		mustChangeArg += "yes"
	} else {
		mustChangeArg += "no"
	}
	cmd := exec.Command("net", "user", username, password, activeArg, mustChangeArg)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("(%s): %w: %s", cmd.String(), err, output)
	}
	return nil
}

// AddADGroupMember calls Add-ADGroupMember on the specified group and username.
func AddADGroupMember(group, username string) (err error) {
	cmd := fmt.Sprintf(`Add-ADGroupMember -Identity "%s" -Members %s -Confirm:$false`, group, username)
	output, err := PSCommand(cmd)
	if err != nil {
		return fmt.Errorf("command '%s' returned: %w: %s", cmd, err, output)
	}
	return nil
}

// RemoveADGroupMember calls Remove-ADGroupMember on the specified group and username.
func RemoveADGroupMember(group, username string) (err error) {
	cmd := fmt.Sprintf(`Remove-ADGroupMember -Identity "%s" -Members %s -Confirm:$false`, group, username)
	output, err := PSCommand(cmd)
	if err != nil {
		return fmt.Errorf("command '%s' returned: %w: %s", cmd, err, output)
	}
	return nil
}

// PSCommand runs the specified command with powershell.
func PSCommand(command string) (output []byte, err error) {
	cmd := exec.Command("powershell", "-nologo", "-noprofile", command)
	stderr := strings.Builder{}
	cmd.Stderr = &stderr
	output, err = cmd.Output()
	if err != nil {
		return
	}
	erroutput := stderr.String()
	if erroutput != "" {
		err = errors.New(erroutput)
		return
	}
	return
}
