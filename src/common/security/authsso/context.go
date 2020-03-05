// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authsso

import (
	"strings"
	"sync"

	"github.com/goharbor/harbor/src/common"
	"github.com/goharbor/harbor/src/common/dao"
	"github.com/goharbor/harbor/src/common/models"
	"github.com/goharbor/harbor/src/common/rbac"
	"github.com/goharbor/harbor/src/common/rbac/project"
	"github.com/goharbor/harbor/src/common/utils/log"
	"github.com/goharbor/harbor/src/core/promgr"
)

const (
	// AuthTokenHeader is the key of auth token header
	AuthTokenHeader  = "Authorization"
)

// SecurityContext implements security.Context interface based on database
type SecurityContext struct {
	user *models.User
	pm   promgr.ProjectManager
	evaluator rbac.Evaluator
	once      sync.Once
}

// NewSecurityContext ...
func NewSecurityContext(user *models.User, pm promgr.ProjectManager) *SecurityContext {
	return &SecurityContext{
		user: user,
		pm:   pm,
	}
}

// IsAuthenticated returns true if the user has been authenticated
func (s *SecurityContext) IsAuthenticated() bool {
	return s.user != nil
}

// GetUsername returns the username of the authenticated user
// It returns null if the user has not been authenticated
func (s *SecurityContext) GetUsername() string {
	if !s.IsAuthenticated() {
		return ""
	}
	return s.user.Username
}

// IsSysAdmin returns whether the authenticated user is system admin
// It returns false if the user has not been authenticated
func (s *SecurityContext) IsSysAdmin() bool {
	if !s.IsAuthenticated() {
		return false
	}
	return s.user.HasAdminRole
}

// IsSolutionUser ...
func (s *SecurityContext) IsSolutionUser() bool {
	return false
}

// Can returns whether the user can do action on resource
func (s *SecurityContext) Can(action rbac.Action, resource rbac.Resource) bool {
	s.once.Do(func() {
		s.evaluator = rbac.NewNamespaceEvaluator("project", func(ns rbac.Namespace) rbac.Evaluator {
			projectID := ns.Identity().(int64)
			proj, err := s.pm.Get(projectID)
			if err != nil {
				log.Errorf("failed to get project %d, error: %v", projectID, err)
				return nil
			}
			if proj == nil {
				return nil
			}

			user := project.NewUser(s, rbac.NewProjectNamespace(projectID, proj.IsPublic()), s.GetProjectRoles(projectID)...)
			return rbac.NewUserEvaluator(user)
		})
	})

	return s.evaluator != nil && s.evaluator.HasPermission(resource, action)
}

// GetProjectRoles ...
func (s *SecurityContext) GetProjectRoles(projectIDOrName interface{}) []int {
	if !s.IsAuthenticated() || projectIDOrName == nil {
		return []int{}
	}

	roles := []int{}
	user, err := dao.GetUser(models.User{
		Username: s.GetUsername(),
	})
	if err != nil {
		log.Errorf("failed to get user %s: %v", s.GetUsername(), err)
		return roles
	}
	if user == nil {
		log.Debugf("user %s not found", s.GetUsername())
		return roles
	}
	project, err := s.pm.Get(projectIDOrName)
	if err != nil {
		log.Errorf("failed to get project %v: %v", projectIDOrName, err)
		return roles
	}
	if project == nil {
		log.Errorf("project %v not found", projectIDOrName)
		return roles
	}
	roleList, err := dao.GetUserProjectRoles(user.UserID, project.ProjectID, common.UserMember)
	if err != nil {
		log.Errorf("failed to get roles of user %d to project %d: %v", user.UserID, project.ProjectID, err)
		return roles
	}
	for _, role := range roleList {
		switch role.RoleCode {
		case "MDRWS":
			roles = append(roles, common.RoleProjectAdmin)
		case "DRWS":
			roles = append(roles, common.RoleMaster)
		case "RWS":
			roles = append(roles, common.RoleDeveloper)
		case "RS":
			roles = append(roles, common.RoleGuest)
		case "LRS":
			roles = append(roles, common.RoleLimitedGuest)
		}
	}

	//continue look for role from SSO
	return s.GetRolesBySSORole(projectIDOrName, roles)
}

func mergeRoles(rolesA, rolesB []int) []int {
	type void struct{}
	var roles []int
	var placeHolder void
	roleSet := make(map[int]void)
	for _, r := range rolesA {
		roleSet[r] = placeHolder
	}
	for _, r := range rolesB {
		roleSet[r] = placeHolder
	}
	for r := range roleSet {
		roles = append(roles, r)
	}
	return roles
}

// GetRolesBySSORole- Get the role of current user to the project from SSO role
func (s *SecurityContext) GetRolesBySSORole(projectIDOrName interface{}, roles []int) []int {
	user := s.user
	project, err := s.pm.Get(projectIDOrName)
	// No user, group or project info
	if err != nil || project == nil || user == nil || len(user.SSORoleList) == 0 {
		return roles
	}

	projectroles := strings.Split(strings.Join(user.SSORoleList, ","), ",")
	log.Debugf("Get project role %v", projectroles)
	for _, element := range projectroles {
		if len(element) ==0 {
			continue
		}
		oneprojectrole := strings.Split(element, ":")
		if len(oneprojectrole) != 2 {
			log.Errorf("Failed to parse project role from SSO %s", element)
		}

		//case-insensitive
		if strings.EqualFold( project.Name , strings.TrimSpace(oneprojectrole[0])) {
			log.Debugf("Get project role from SSO %s", element)
			//case-insensitive
			trimedssorole := strings.ToLower(strings.TrimSpace(oneprojectrole[1]))
			switch trimedssorole{
			case "admin":
				roles = append(roles, common.RoleProjectAdmin)
			case "developer":
				roles = append(roles, common.RoleDeveloper)
			case "guest":
				roles = append(roles, common.RoleGuest)
			case "master":
				roles = append(roles, common.RoleMaster)
			case "limitedguest":
				roles = append(roles, common.RoleLimitedGuest)
			}
			break
		}
	}
	log.Debugf("Get project role from SSO %v", roles)
        return mergeRoles(roles, s.GetRolesByGroup(projectIDOrName))
}

// GetRolesByGroup - Get the group role of current user to the project
func (s *SecurityContext) GetRolesByGroup(projectIDOrName interface{}) []int {
	var roles []int
	user := s.user
	project, err := s.pm.Get(projectIDOrName)
	// No user, group or project info
	if err != nil || project == nil || user == nil || len(user.GroupList) == 0 {
		return roles
	}
	// Get role by Group ID
	roles, err = dao.GetRolesByGroupID(project.ProjectID, user.GroupIDs)
	if err != nil {
		return nil
	}
	return roles
}

// GetMyProjects ...
func (s *SecurityContext) GetMyProjects() ([]*models.Project, error) {
	// query from db first
	result, err := s.pm.List(
		&models.ProjectQueryParam{
			Member: &models.MemberQuery{
				Name:     s.GetUsername(),
				GroupIDs: s.user.GroupIDs,
			},
		})
	if err != nil {
		return nil, err
	}

	// combine with the attribute from SSO
	// append project from sso and exists in Harbor
	projectroles := strings.Split(strings.Join(s.user.SSORoleList, ","), ",")
	log.Debugf("Get project role %v", projectroles)
	for _, element := range projectroles {
		if len(element) ==0 {
			continue
		}
		oneprojectrole := strings.Split(element, ":")
		if len(oneprojectrole) != 2 {
			log.Errorf("Failed to parse project role from SSO %s", element)
			continue
		}
		project, err := s.pm.Get(strings.TrimSpace(oneprojectrole[0]))
		if err != nil {
			log.Errorf("failed to get project %s: %v", oneprojectrole[0], err)
			continue
		}
		if project == nil {
			log.Errorf("did not find project in harbor, ignore it: %s", oneprojectrole[0])
			continue
		}
		log.Debugf("Get project from SSO %v", project)
                result.Projects = append(result.Projects, project)
        }

	return result.Projects, nil
}
